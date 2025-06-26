#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test making modifications on every functions in the file

. test/common.sh

# comment below line to perform a real test
CheckDiff=1

readonly KernelTestDir="drivers/gpu"
# readonly KernelTestDir="net"
# readonly KernelTestDir="sound"
# readonly KernelTestDir="virt"
# readonly KernelTestDir="security"
# readonly KernelTestDir="ipc"
# readonly KernelTestDir="crypto"
# readonly KernelTestDir="certs"
# readonly KernelTestDir="block"
# readonly KernelTestDir="mm"
# readonly KernelTestDir="fs"
readonly KernelTestDir="kernel"

IgnoreFunctions=(
	"intel_atomic_commit"
	"drm_mode_atomic_ioctl"

	"dma_fence_work_init"

	"drm_dp_mst_dump_sideband_msg_tx"	# forbidden
	"drm_gem_object_put"	# forbidden
	"i915_gem_object_lock"	# forbidden
	"update_context_prio"	# forbidden
	"__context_lookup"	# forbidden
	"fw_domain_wait_ack_set"	# forbidden
	"fw_domain_arm_timer"	# forbidden
)

testFile()
{
	local file=$1
	local mode=$2
	local action=$3

	local texttoinsert='__asm__ __volatile__("nop");'
	# local texttoinsert='printk(KERN_ERR "DEKU (fun:%s)", __func__);'
	local tags=`./tags "$file" "$texttoinsert"`
	local funcs=`sed -nr "s/.*\b(.+):([0-9]+)$/\1/p" <<< "$tags"`
	readarray funcs <<< "$funcs"

	cp "$file" /tmp/deku_temp

	if [[ $mode == "all-at-once" ]]; then
		logErr "Modify all functions in the $file"
		./tags mod_funcs -2 "$file" "$texttoinsert" --exclude ${IgnoreFunctions[*]}
		[[ "$CheckDiff" ]] && return
		./deku --workdir="$WORKDIR" --board=$CROS_BOARD \
			   --target=localhost:2233 \
			   $action
		local rc=$?
		if [[ $rc != 0 ]]; then
			local srcfile="${file#$SOURCE_DIR/}"
			cp /tmp/deku_temp "$file"
			logErr "Error code: $rc"
			[[ \
				$rc != $ERROR_FORBIDDEN_MODIFY && \
				$rc != $ERROR_DEPEND_MODULE_NOT_LOADED \
			]] && exit 1
			logErr "This error is expected"
		fi
	elif [[ $mode == "one-at-once" ]]; then
		for fun in "${funcs[@]}"; do
			fun=`echo "$fun" | xargs`
			logErr "Modify one function: $fun in the $file"
			./tags mod_funcs $fun "$file" "$texttoinsert"
			./deku --workdir="$WORKDIR" --board=$CROS_BOARD \
				   --target=localhost:2233 \
				   $action || { cp /tmp/deku_temp "$file"; }
			cp /tmp/deku_temp "$file"
		done
	else
		for fun in "${funcs[@]}"; do
			fun=`echo "$fun" | xargs`
			logErr "Modify function: $fun in the $file"
			./tags mod_funcs $fun "$file" "$texttoinsert"
			./deku --workdir="$WORKDIR" --board=$CROS_BOARD \
				   --target=localhost:2233 \
				   $action || { cp /tmp/deku_temp "$file"; }
		done
	fi

	echo "$file" >> "$complitedfile"

	return

	cp /tmp/deku_temp "$file"
	# unload
	logStep "Unload..."
	if [[ $action == "deploy" ]]; then
		./deku --workdir="$WORKDIR" --board=$CROS_BOARD \
			   --target=localhost:2233 \
			   $action
	fi
}

IgnoreFiles=(
	"drivers/gpu/drm/i915/display/intel_dpll.c" # tags error

	"drivers/gpu/drm/i915/i915_request.c" # bad function align for __i915_sw_fence_init
	"drivers/gpu/drm/i915/display/intel_display.c" # bad function align for __i915_sw_fence_init
	"drivers/gpu/drm/i915/gt/intel_timeline.c" # bad function align for __i915_sw_fence_init

	"drivers/gpu/drm/i915/i915_memcpy.c" # static DEFINE_STATIC_KEY_FALSE(has_movntdqa);
	"drivers/gpu/drm/drm_cache.c" # static DEFINE_STATIC_KEY_FALSE(has_movntdqa);

	"drivers/gpu/drm/i915/display/intel_combo_phy.c" # lack of rela.rodata section ?

	"drivers/gpu/drm/drm_gem.c" # forbidden changes
	"drivers/gpu/drm/i915/intel_uncore.c" # forbidden changes
	"drivers/gpu/drm/i915/gt/intel_gtt.c" # forbidden changes
	"drivers/gpu/drm/i915/gt/uc/intel_guc_submission.c" # forbidden changes

	# "net/bluetooth/rfcomm/core.c" # no support for klp functions index
	# "net/sysctl_net.c" # no support for klp functions index

	"net/core/scm.c" # failed to set ftrace filter for function 'scm_check_creds' (-22)
	"net/bluetooth/rfcomm/core.c" #  Device or resource busy
	"net/ipv6/udp_offload.c" # the symbol skb_gro_incr_csum_unnecessary exists also in net/ipv4/udp_offload.c need to improve findSymbolIndex function to distinguish files with the same name, maybe by matching other functions in the file?
	"net/core/link_watch.c" # by changing __linkwatch_run_queue func and after log-in/log-out kernel notifies about corruped linked list

	"sound/soc/codecs/cs42l42.c" # modpost: module deku_17a6b2d7_cs42l42 uses symbol cs42l42_page_range from namespace SND_SOC_CS42L42_CORE, but does not import it.
	"sound/soc/codecs/cs42l42-i2c.c" # modpost: module deku_24b8fc78_cs42l42_i2c uses symbol cs42l42_resume_restore from namespace SND_SOC_CS42L42_CORE, but does not import it.
	"sound/soc/intel/boards/sof_maxim_common.c"
	"sound/soc/intel/boards/sof_sdw_hdmi.c"
	"sound/soc/intel/boards/glk_rt5682_max98357a.c"
	"sound/soc/intel/boards/sof_sdw_max98373.c"
	"sound/soc/intel/boards/cml_rt1011_rt5682.c"
	"sound/soc/intel/boards/bxt_da7219_max98357a.c"
	"sound/soc/intel/boards/sof_da7219.c"
	"sound/soc/intel/boards/sof_rt5682.c"
	"sound/soc/intel/boards/sof_cs42l42.c"
	"sound/soc/intel/boards/skl_hda_dsp_common.c"
	"sound/soc/intel/boards/sof_nau8825.c"
	"sound/soc/intel/boards/sof_ssp_amp.c"
	"sound/soc/sof/sof-client-probes.c"
	"sound/soc/sof/intel/byt.c"
	"sound/soc/sof/intel/hda-probes.c"
	"sound/soc/sof/intel/mtl.c"
	"sound/soc/sof/intel/tgl.c"
	"sound/soc/sof/intel/skl.c"
	"sound/soc/sof/intel/cnl.c"
	"sound/soc/sof/intel/pci-tng.c"
	"sound/soc/sof/intel/apl.c"
	"sound/soc/sof/intel/bdw.c"
	"sound/soc/sof/intel/icl.c"
	"sound/soc/sof/intel/hda-dsp.c"
	"sound/soc/sof/pm.c"
	"sound/hda/intel-dsp-config.c"

	"security/selinux/ss/services.c" # error: call to undeclared function 'cond_compute_av'; ISO C99 and later do not support implicit function declarations
	"security/selinux/ss/conditional.c"
	"security/selinux/ss/policydb.c"

	"crypto/skcipher.c" # modpost: module deku_bbabb7b1_skcipher uses symbol crypto_cipher_setkey from namespace CRYPTO_INTERNAL, but does not import it.
	"crypto/essiv.c"
	"crypto/xts.c"
	"crypto/cmac.c"
	"crypto/ccm.c"
	"crypto/ctr.c"
	"crypto/ecdh.c" # ld.lld: error: duplicate symbol: init_module

	"mm/percpu.c" # symbol '__per_cpu_start' not found in symbol table
	"mm/migrate.c" # Device or resource busy
	"mm/vmscan.c"
	"mm/mlock.c" # module: x86/modules: Skipping invalid relocation target, existing value is nonzero for type 4, loc 00000000b8e081f9, val ffffffffa18607ec
	"mm/compaction.c" # compaction is still transitioning...
	"mm/oom_kill.c"
	"mm/vmalloc.c" # vmalloc error: size 16384, vm_struct allocation failed, mode:0xdc0(GFP_KERNEL|__GFP_ZERO), nodemask=(null),cpuset=/,mems_allowed=0

	"fs/sync.c" # x86/modules: Skipping invalid relocation target, existing value is nonzero for type 4, loc 000000001e5f9ec9, val ffffffff85c607ec
	"fs/notify/inotify/inotify_user.c"
	"fs/ecryptfs/kthread.c" # kthread is still transitioning...
	"fs/jbd2/journal.c"
	"fs/exec.c" # BUG: kernel NULL pointer dereference, address: 0000000000000000
	"fs/proc/inode.c" # modpost: missing MODULE_LICENSE() in
	"fs/ext4/sysfs.c" # Fail to adjust relocations: can't find properly symbol index because there are multiple symbols with the same name
	"fs/notify/mark.c" # general protection fault, probably for non-canonical address 0x7f789ec35ca56728: 0000 [#1] PREEMPT SMP NOPTI | fsnotify_connector_destroy_workfn+0x5b/0x6c

	"kernel/uid16.c" # module: x86/modules: Skipping invalid relocation target, existing value is nonzero for type 4, loc 000000000ea5971f, val ffffffffb96607ec
	"kernel/sys.c"
	"kernel/signal.c"
	"kernel/fork.c"
	"kernel/hung_task.c" # hung_task is still transitioning...
	"kernel/sched/wait.c"
	"kernel/kthread.c"
	"kernel/irq/manage.c"
	"kernel/smpboot.c"
	"kernel/audit.c"
	"kernel/livepatch/core.c" ############
	"kernel/livepatch/transition.c"
	"kernel/module.c"
	"kernel/reboot.c" # module: overflow in relocation type 11 val ffffa13780c0a0c1 | module: `deku_691841e4_reboot' likely not compiled with -mcmodel=kernel
	"kernel/kallsyms.c"
	"kernel/user.c"
	"kernel/auditsc.c"
	"kernel/exec_domain.c" # cleanup_module+0x98d/0xf77 [deku_0365e535_exec_domain dcccbd0b93d21b11f56a52c7ce0b8c011b4dd19d]
	"kernel/debug/kdb/kdb_support.c" # error: use of undeclared identifier 'kdb_flags'
	"kernel/debug/kdb/kdb_main.c" # error: use of undeclared identifier 'CONFIG_KDB_DEFAULT_ENABLE'
	"kernel/debug/kdb/kdb_bt.c"
	"kernel/debug/kdb/kdb_debugger.c"
	"kernel/debug/kdb/kdb_bp.c"
	"kernel/debug/kdb/kdb_io.c"
	"kernel/debug/debug_core.c"
	"kernel/debug/gdbstub.c"
	"kernel/power/snapshot.c" # deku_8cd30280_snapshot: Unknown symbol buffer (err -2)
	"kernel/irq/irqdesc.c" # Device or resource busy
)

if [[ $CHROMEOS_KERNEL_VER == "5_15" ]]; then
	IgnoreFiles+=("drivers/gpu/drm/drm_gem_shmem_helper.c") # forbidden changes
fi

modulesList()
{
	local results=()
	local modules=`find "$WORKDIR" -maxdepth 1 -type d -regextype sed -regex ".\+/deku_[a-f0-9]\{8\}.\+" -printf "%f\n"`

	while read -r module; do
		local path="$WORKDIR/$module/$module.ko"
		[ ! -f "$path" ] && { logErr "No .ko file: $path"; continue; }
		results+=("$module `md5sum $path`")
	done <<< "$modules"
	printf "%s\n" "${results[@]}"
}

commitNewPattern()
{
	MAIN_PATH=`dirname "$0"`
	initDEKUForChromebook "no_init"
	exportVars "$WORKDIR"
	modulesList > $MAIN_PATH/${KernelTestDir#/#_}_$CHROMEOS_KERNEL_VER
}

exportVars()
{
	export SOURCE_DIR="/build/brya/var/cache/portage/sys-kernel/chromeos-kernel-$CHROMEOS_KERNEL_VER/source"
}

main()
{
	MAIN_PATH=`dirname "$0"`

	local complitedfile="$MAIN_PATH/complited"

# 	local modules=`find workdir_test -type d -name "*" | tr '\n' ' '`
# 	# echo "$modules"
# 	# return
# 	read -a modules <<< "$modules"
# 	for moduledir in "${modules[@]}"; do
# 		# moduledir=`echo "$moduledir" | xargs`
# 		echo "==========$moduledir========="
# 	done
# return
	[[ "$CheckDiff" != "" ]] && rm -f "$complitedfile"

	if [[ -f "$complitedfile" ]]; then
		logInfo "Continue..."
		sleep 5
		initDEKUForChromebook no_init
	else
		initDEKUForChromebook
	fi
	exportVars
	chmod +x ./tags
	local files=`find "$SOURCE_DIR/$KernelTestDir" -maxdepth 30 -type f -name "*.c" | tr '\n' ' '`
	read -a files <<< "$files"
	for file in "${files[@]}"; do
		[[ "$file" == "" ]] && break
		local objfile=${file/source/}
		objfile=${objfile/.c/.o}
		local shortfile="${file#$SOURCE_DIR/}"

		[[ ! -f $objfile ]] && { logDebug "Skip: $shortfile"; continue; }
		[[ ${IgnoreFiles[*]} == *"$shortfile"* ]] && { logInfo "Ignore $shortfile"; continue; }
		grep -q "$file" "$complitedfile" 2>/dev/null && { logInfo "Already ran: $shortfile"; continue; }

		if [[ "$CheckDiff" ]]; then
			testFile "$file" "all-at-once" "deploy" 2>> "$MAIN_PATH/output" &
		else
			testFile "$file" "all-at-once" "deploy" 2>> "$MAIN_PATH/output"
		fi
	done

	if [[ "$CheckDiff" ]]; then
		wait
		./deku --workdir="$WORKDIR" --board=$CROS_BOARD build

		local modules=`find "$WORKDIR" -maxdepth 1 -type d -regextype sed -regex ".\+/deku_[a-f0-9]\{8\}.\+" -printf "%f\n"`

		echo "Check results..."
		while read -r module; do
			local path="$WORKDIR/$module/$module.ko"
			[ ! -f "$path" ] && { echo "NO MODULE FOUND: $path"; continue; }
			local sum=`md5sum $path`
			grep -q "$sum" "$MAIN_PATH/${KernelTestDir#/#_}_$CHROMEOS_KERNEL_VER" || { echo "CHANGED: $sum"; exit 1; }
			path=$(<"$WORKDIR/$module/$FILE_SRC_PATH")
			echo "$SOURCE_DIR/$path" >> "$complitedfile"
		done <<< "$modules"
		echo "============== Now let's disable checking diff, undo all changes in kernel sources and run again =============="
	fi
	echo "============== FINISH =============="
}

main $@
# commitNewPattern $@

# local skipparam=("-o" "-Wdeclaration-after-statement")
# echo "ccflags-remove-y=-Wdeclaration-after-statement" >> $makefile
