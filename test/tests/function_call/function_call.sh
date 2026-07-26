#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test that changes are properly applied on the running kernel.
# The test uses qemu to run test kernel.

FILES="net/ipv4/arp.c net/ipv4/tcp_ipv4.c fs/timerfd.c fs/readdir.c mm/mmap.c mm/vma.c kernel/sched/fair.c kernel/sched/fair_eevdf.c kernel/sched/core.c net/core/neighbour.c net/ethernet/eth.c"
DESCRIPTION="Function call"
. test/common.sh

functionCallTest()
{
	local file=$1
	local function=$2
	local cmd=$3
	local text="[$SCRIPT_NAME] DEKU $function test"
	local srcDir=$SOURCE_DIR

	logStep "Pre the $file..."
	revertChanges
	dekuDeploy || exitError 1
	local sudo=
	[[ $VM_TEST ]] && sudo=sudo || cmd=${cmd//sudo/}
	loadedModules=$(remoteShOut "find /sys/module -name .note.deku -type f -exec $sudo grep deku_ {} \;")
	[[ "$loadedModules" ]] && logErr "Detected unexpected loaded modules: $loadedModules" && exitError 2

	logStep "Check the $file..."

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"$text\");"

	dekuDeploy
	local ret=$?
	[[ $ret == $ERROR_FORBIDDEN_MODIFY ]] && { logInfo "Skip"; return 0; }
	[[ $ret != 0 ]] && exitError 3
	clearLogs

	runCmdAndCheckIfDmesgContains "$cmd" "$text" || exitError 4

	return 0
}

test()
{
	local srcDir=$SOURCE_DIR
	local fairSched="kernel/sched/fair.c"
	local downloadCmd="curl --silent --head unknown.com 2>&1 > /dev/null; curl --silent --head google.com 2>&1 > /dev/null; curl --silent --head google.eu 2>&1 > /dev/null; curl --silent --head bing.com 2>&1 > /dev/null;"
	downloadCmd+="wget --quiet --spider unknown.com 2>&1 > /dev/null; wget --quiet --spider google.com 2>&1 > /dev/null; wget --quiet --spider google.eu 2>&1 > /dev/null; wget --quiet --spider bing.com 2>&1 > /dev/null;"
	[[ -s "$srcDir/kernel/sched/fair_eevdf.c" ]] && fairSched="kernel/sched/fair_eevdf.c"

	if [[ ! $ANDROID ]]; then
		functionCallTest "net/ipv4/arp.c" "arp_create" "sudo ip -s -s neigh flush all >/dev/null; $downloadCmd"
	fi
	functionCallTest "net/ipv4/tcp_ipv4.c" "tcp_v4_connect" "$downloadCmd"
	functionCallTest "fs/timerfd.c" "timerfd_triggered" "sleep 2; dmesg | grep -q timerfd_triggered || { grep -q CHROMEOS /etc/lsb-release && /usr/local/autotest/bin/autologin.py > /dev/null 2>&1; }"
	functionCallTest "fs/readdir.c" "filldir64" "timeout 10 nautilus"
	if isKernelNewerOrEqualThan v6.14; then
		functionCallTest "mm/vma.c" "mmap_region" "sleep 2"
	else
		if [[ ! $ANDROID ]]; then
			functionCallTest "mm/mmap.c" "mmap_region" "sleep 2"
		fi
	fi
	local pickTaskFun=pick_next_task_fair
	isKernelNewerThan v6.18 && pickTaskFun=pick_task_fair
	
	functionCallTest $fairSched "$pickTaskFun" "sleep 1"
	# ? functionCallTest "kernel/sched/core.c" "select_task_rq" "sleep 2"
	# functionCallTest "net/core/neighbour.c" "neigh_alloc" "sudo ip -s -s neigh flush all; $downloadCmd"
	if [[ ! $ANDROID ]]; then
		functionCallTest "net/ethernet/eth.c" eth_type_trans "sudo ip -s -s neigh flush all >/dev/null; $downloadCmd"
	fi
}

main()
{
	test
	#
	# TODO: Check if every "caller" exists in out object file in: generateDiffObject function
	#		if traceable {
	#		modSyms = append(modSyms, fun)
	#	} else {
	#		for _, sym := range callers {
	#+			// TODO: check if sym exists in the oFile
	#			modSyms = append(modSyms, sym)
	#			extractSyms = append(extractSyms, sym)
	#		}
	#	}
	#	extractSyms = append(extractSyms, fun)
	#
}

main $@
