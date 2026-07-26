#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test whether modify no-traceable functions are properly detected

FILES="drivers/gpu/drm/drm_dp_mst_topology.c drivers/gpu/drm/display/drm_dp_mst_topology.c drivers/net/wireless/ath/ath10k/pci.c drivers/cpuidle/cpuidle.c drivers/base/node.c drivers/gpu/vga/vgaarb.c drivers/md/dm-table.c"
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
	local srcDir=$SOURCE_DIR
	local files=`find "$BUILD_DIR/drivers" -name "*.o" -not -path "*lib*"`
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
	local srcDir=$SOURCE_DIR

	revertChanges

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"\");"

	logStep -n "Respect non-traceable function in $file... "
	out=$(dekuDeploy --stdout -v)
	local res=$?
	if [[ $status == "fail" ]]; then
		[[ $res == 0 ]] && { logErr "Fail"; exitError; }
		grep -q "function is forbidden to modify" <<< "$out" || { logErr "Fail"; exitError; }
		grep -q "Can't apply changes to " <<< "$out" || { logErr "Fail"; exitError; }
		if [[ $# == 3 ]]; then
			grep -q "The function is non-local" <<< "$out" || { logErr "Fail"; exitError; }
			logStep "OK"
			return
		fi
	else
		[[ $res != 0 ]] && { logErr "Fail"; exitError; }
	fi

	shift 3
	for sym in "$@"
	do
		sym=${sym:2}
		if ! grep -q "The non-traceable function $function is (in)directly called from .*traceable function ${sym}\b" <<< "$out"; then
			logErr "Function $function should be referenced from: ${sym}"
			exitError
		fi
	done

	local cnt=`grep -e "^The non-traceable function" <<< "$out" | wc -l`
	if [[ $cnt != $# ]]; then
		logErr "More references detected than expected"
		>&2 grep -e "^The non-traceable function" <<< "$out"
		exitError
	fi

	logStep "OK"
}

test()
{
	# findNontraceable LOCAL # uncomment to find non-traceable functions
	# findNontraceable GLOBAL # uncomment to find non-traceable functions

	if [[ $KERNEL_VERSION == v5.10* ]]; then
		if [[ $CHROMEOS ]]; then
			checkNontraceable drivers/gpu/drm/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply"
		else
			checkNontraceable drivers/gpu/drm/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply.isra.0"
		fi
		# checkNontraceable drivers/base/node.c cpumap_show fail "v:dev_attr_cpumap"
		# checkNontraceable drivers/gpu/vga/vgaarb.c vga_update_device_decodes "f:__vga_set_legacy_decoding.cold" "f:vga_arbiter_notify_clients.part.0" "And __vga_set_legacy_decoding > __vga_set_legacy_decoding.cold"
		checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
		return
	fi
	# checkNontraceable drivers/net/wireless/ath/ath10k/pci.c ath10k_pci_write32 fail # v:ath10k_pci_hif_ops
	# checkNontraceable drivers/net/wireless/ath/ath10k/pci.c ath10k_pci_read32 fail # v:ath10k_pci_hif_ops
# 		checkNontraceable drivers/cpuidle/cpuidle.c enter_s2idle_proper ok cpuidle_enter_s2idle
# 		checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply"
# checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
	if [[ $KERNEL_VERSION == v5.15* ]]; then
		if [[ $CHROMEOS ]]; then
			checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply"
		else
			checkNontraceable drivers/gpu/drm/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply"
		fi
		checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
		return
	fi

	if [[ $KERNEL_VER == v6.1 || $KERNEL_VERSION == v6.1.* ]]; then
		checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply"
		return
	fi

	if [[ $KERNEL_VERSION == v6.6* ]]; then
		checkNontraceable drivers/cpuidle/cpuidle.c enter_s2idle_proper ok f:cpuidle_enter_s2idle
		checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply"
		checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
		return
	fi

	if [[ $KERNEL_VERSION == v6.12* ]]; then
		checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply"
		checkNontraceable drivers/cpuidle/cpuidle.c enter_s2idle_proper ok f:cpuidle_enter_s2idle
		checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
		return
	fi

	if [[ $KERNEL_VERSION == v6.14.* || $KERNEL_VERSION =~ ^v[0-9]+\.[0-9]+-rc[0-9]+$ ]]; then
		checkNontraceable drivers/cpuidle/cpuidle.c enter_s2idle_proper ok f:cpuidle_enter_s2idle
		checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply"
		checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
		return
	fi

	#TODO: disallow livepatch the notraceable functions that are sed be variables
	if [[ $KERNEL_VERSION != v6.14.* && $KERNEL_VERSION != v6.18.* ]]; then
		checkNontraceable drivers/net/wireless/ath/ath10k/pci.c ath10k_pci_write32 fail # v:ath10k_pci_hif_ops
	fi
	if [[ $KERNEL_VERSION != v6.18.* ]]; then
		checkNontraceable drivers/net/wireless/ath/ath10k/pci.c ath10k_pci_read32 fail # v:ath10k_pci_hif_ops
	fi

	if [[ $VM_TEST ]]; then
		remoteSh "sudo modprobe drm_display_helper"
		if [[ $KERNEL_VERSION != v7.0.* ]]; then
			checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_atomic_check_payload_alloc_limits ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply" "f:drm_dp_mst_atomic_check_payload_alloc_limits.cold"
		else
			: #checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok "f:process_single_tx_qlock" "f:drm_dp_queue_down_tx" "f:drm_dp_mst_wait_tx_reply" "f:drm_dp_mst_dump_sideband_msg_tx.cold"
		fi
		# TODO: add better key migration
		# checkNontraceable drivers/cpuidle/cpuidle.c enter_s2idle_proper ok f:cpuidle_enter_s2idle
	else
		checkNontraceable drivers/gpu/drm/display/drm_dp_mst_topology.c drm_dp_mst_dump_sideband_msg_tx ok f:process_single_tx_qlock f:drm_dp_queue_down_tx f:drm_dp_mst_wait_tx_reply.isra.0
	fi
	[[ $KERNEL_VERSION != v6.1.* ]] && checkNontraceable drivers/cpuidle/cpuidle.c cpuidle_enter_state fail # f:cpuidle_enter

	[[ $KERNEL_VERSION != v5.15.* ]] && checkNontraceable drivers/md/dm-table.c dm_table_get_size fail
}

main()
{
	test
}

main $@
