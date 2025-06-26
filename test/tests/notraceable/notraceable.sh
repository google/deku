#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test whether modify no-traceable functions are properly detected

FILES="drivers/gpu/drm/drm_dp_mst_topology.c drivers/net/wireless/ath/ath10k/pci.c drivers/cpuidle/cpuidle.c drivers/base/node.c drivers/gpu/vga/vgaarb.c drivers/md/dm-table.c"
DESCRIPTION="No traceable functions"
. test/common.sh

TAGS=test/tags/tags

function isTraceable()
{
	local file=$1
	local symbol=$2

	./deku isTraceable "$file" $symbol
}

function findNontraceable()
{
	local bind=$1
	local srcDir=$(sourceDir $KERNEL_VER)
	local files=`find "$BUILD_DIR/drivers" -name "*.o"  -not -path "*lib*"`
	while read -r file;
	do
		local funcs=`readelf -sW "$file" | grep FUNC | grep $bind | grep -o '[^ ]*$'`
		local cfile=${file/.o/.c}
		cfile=${cfile#*$BUILD_DIR/}
		cfuncs=`$TAGS "$srcDir/$cfile" | sed -nr "s/.*\ (\w+):(.+)$/\1/p" 2>/dev/null`
		[[ $? != 0 ]] && continue
		while read -r fun;
		do
			[[ $fun == "" ]] || [[ $fun == *init* ]] || [[ $fun == *exit* ]] || [[ $fun == *cleanup* ]] && continue

			if ! isTraceable "$file" $fun; then
				if grep -q $fun <<< "$cfuncs"; then
					local reference=$(./elfutils --referenceFrom -f "$file" -s $fun)
					if [[ "$reference" ]]; then
						# echo "$cfile: $fun - $reference"
						reference=$(echo "$reference" | tr '\n' ' ')
						logStep "Use following line:"
						if [[ "$bind" == "LOCAL" ]]; then
							echo "checkNontraceable $cfile $fun ok $reference"
						else
							echo "checkNontraceable $cfile $fun fail $reference"
						fi
					fi
				fi
			fi
		done <<< "$funcs"

	done <<< "$files"
}

checkNontraceable()
{
	local file=$1
	local function=$2
	local status=$3
	local srcDir=$(sourceDir $KERNEL_VER)

	revertChanges

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"\");"

	logStep -n "Respect non-traceable function in $file... "
	out=$(dekuBuild --log -v)
	local res=$?
	if [[ $status == "fail" ]]; then
		[[ $res == 0 ]] && { logErr "Fail"; exit 1; }
		grep -q "forbidden" <<< "$out" || { logErr "Fail"; exit 2; }
		grep -q "Can't apply changes to the" <<< "$out" || { logErr "Fail"; exit 3; }
		if [[ $# == 3 ]]; then
			grep -q "The function is non-local" <<< "$out" || { logErr "Fail"; exit 4; }
			logStep "OK"
			return
		fi
	else
		[[ $res != 0 ]] && { logErr "Fail"; exit 5; }
	fi

	shift 3
	for sym in "$@"
	do
		if ! grep -q "^$sym\b" <<< "$out"; then
			echo "Function $function should be referenced from: ${sym#*:}"
			exit 6
		fi
	done

	local cnt=`grep -e "^f:" -e "^v:" <<< "$out" | wc -l`
	if [[ $cnt != $# ]]; then
		logErr "More references detected than expected"
		>&2 grep -e "f:" -e "v:" <<< "$out"
		exit 7
	fi

	logStep "OK"
}

test()
{
	# findNontraceable LOCAL # uncomment to find non-traceable functions
	# findNontraceable GLOBAL # uncomment to find non-traceable functions

	if [[ $KERNEL_VER == v5.10.* ]]; then
		checkNontraceable drivers/gpu/drm/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply.isra.0"
		checkNontraceable drivers/base/node.c cpumap_show fail "v:dev_attr_cpumap"
		checkNontraceable drivers/gpu/vga/vgaarb.c vga_update_device_decodes fail "f:__vga_set_legacy_decoding.cold" "f:vga_arbiter_notify_clients.part.0"
		checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
		return
	fi

	#TODO: disallow livepatch the notraceable functions that are sed be variables
	checkNontraceable drivers/net/wireless/ath/ath10k/pci.c ath10k_pci_write32 fail # v:ath10k_pci_hif_ops
	checkNontraceable drivers/net/wireless/ath/ath10k/pci.c ath10k_pci_read32 fail # v:ath10k_pci_hif_ops

	if [[ $KERNEL_VER == v6.8 ]] || [[ $KERNEL_VER == v6.11 ]]; then
		checkNontraceable drivers/cpuidle/cpuidle.c enter_s2idle_proper ok f:cpuidle_enter_s2idle
	else
		checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok f:process_single_tx_qlock f:drm_dp_queue_down_tx f:drm_dp_mst_wait_tx_reply.isra.0
	fi
	checkNontraceable drivers/cpuidle/cpuidle.c cpuidle_enter_state fail # f:cpuidle_enter

	if [[ $KERNEL_VER != v6.8 ]] && [[ $KERNEL_VER != v6.11 ]]; then
		checkNontraceable drivers/base/node.c cpumap_show fail # "dev_attr_cpumap"
		checkNontraceable drivers/gpu/vga/vgaarb.c vga_update_device_decodes fail # f:__vga_set_legacy_decoding.cold f:vga_arbiter_notify_clients.part.0"
	fi

	[[ $KERNEL_VER != v5.15.* ]] && checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
}

main()
{
	if [[ $LOCAL_TEST != "" ]]; then
		:
	else
		test
	fi
}

main $@
