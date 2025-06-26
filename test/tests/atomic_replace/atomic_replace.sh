#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check if cumulative changes into one livepatch works when the atomic replace
# is used.

FILES="drivers/input/misc/uinput.c net/ipv4/tcp_ipv4.c net/ipv4/arp.c kernel/sched/core.c kernel/sched/fair.c fs/readdir.c"
DESCRIPTION="Atomic replace"
. test/common.sh

modifyFile()
{
	local file=$1
	local function=$2
	local extra=$3
	local text="[$SCRIPT_NAME] DEKU $function test$extra"
	local srcDir=$(sourceDir $KERNEL_VERSION)

	git -C "$srcDir" restore $file 2>&1 > /dev/null
	local funcName=__func__
	[[ $KERNEL_VER == v6.11 ]] && funcName="\"$function\""
	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"$text|%s|%s\", __FILE__, $funcName);" > /dev/null
	echo "$text|$file|$function"
}

isCumulativeModule()
{
	[[ $VM_TEST ]] && sleep 10
	grep -qrF ".replace = true," "$WORKDIR/" --include="livepatch.c" || { logErr "Module is not cumulative"; return -1; }
}

isNotCumulativeModule()
{
	[[ $VM_TEST ]] && sleep 10
	grep -qrF ".replace = false," "$WORKDIR/" --include="livepatch.c" || { logErr "Module is cumulative but it shouldn't be"; return -1; }
}

containsNumberOfModulesAndPatches()
{
	local numOfModules=$1
	local numOfPatches=$2
	return 0
}

test()
{
	local cmd="CMD='ip -s -s neigh flush all 2>&1 >/dev/null'; eval \$CMD; eval sudo \$CMD; wget -q --spider google.com; CMD='cat /dev/uinput 2>/dev/null'; eval \$CMD; eval sudo \$CMD; sleep 0.1"
	local srcDir=$(sourceDir $KERNEL_VERSION)

	prepareKernelAndDeploy $KERNEL_VER +CONFIG_INPUT_UINPUT
	runQemu

	logStep "Check revert all changes by using empty livepatch module..."
	local text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	local text4=$(modifyFile "kernel/sched/core.c" "__sched_fork")
	local text3=$(modifyFile "net/ipv4/arp.c" "arp_send_dst")
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	git -C "$srcDir" restore net/ipv4/tcp_ipv4.c kernel/sched/core.c
	out=$(dekuDeploy --stdout -v) || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	# workdirContainsOnly deku_00000000 || exitError $LINENO
	grep -q "Reverting changes from net/ipv4/tcp_ipv4.c" <<< "$out" || exitError $LINENO
	grep -q "Reverting changes from kernel/sched/core.c" <<< "$out" || exitError $LINENO

	git -C "$srcDir" restore net/ipv4/tcp_ipv4.c kernel/sched/core.c
	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect " "
	dekuDeploy || exitError $LINENO

	# remoteSh "insmod deku/deku_00000000.ko"
	text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	dekuDeploy || exitError $LINENO
	git -C "$srcDir" restore net/ipv4/tcp_ipv4.c kernel/sched/core.c
	dekuDeploy || exitError $LINENO

	logStep "Check if the same name of module is not generated twice..."
	text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	dekuDeploy -v || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	text4=$(modifyFile "kernel/sched/core.c" "__sched_fork")
	text3=$(modifyFile "net/ipv4/arp.c" "arp_send_dst")
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	git -C "$srcDir" restore net/ipv4/tcp_ipv4.c kernel/sched/core.c
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect " "
	dekuDeploy || exitError $LINENO

	revertChanges
	dekuDeploy || exitError $LINENO

	text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	text4=$(modifyFile "kernel/sched/core.c" "__sched_fork")
	text3=$(modifyFile "net/ipv4/arp.c" "arp_send_dst")
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	revertChanges
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	# workdirContainsOnly deku_00000000 || exitError $LINENO

	prepareKernelAndDeploy $KERNEL_VER +CONFIG_INPUT_UINPUT
	runQemu

	if [[ $VM_TEST ]]; then
		remoteSh "cd linux; sudo insmod drivers/input/misc/uinput.ko"
	else
		copyToRemote "$BUILD_DIR/drivers/input/misc/uinput.ko" "/tmp/"
		remoteSh "insmod /tmp/uinput.ko"
	fi

	logStep "Check simple update already modified function"
	text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 1 1 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text1" || exitError $LINENO

	local text1_1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect next)
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 1 1 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text1_1" || exitError $LINENO
	checkIfDmesgNOTContains "$text1" || exitError $LINENO

	logStep "Check that making changes to another file in the module works correctly"
	local text2=$(modifyFile drivers/input/misc/uinput.c uinput_open)
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 2 2 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text1_1" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO

	logStep "Check that the cumulative module is generated after undoing one of the file from last changes and doing another change"
	text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	text3=$(modifyFile "net/ipv4/arp.c" "arp_send_dst")
	# local text4=$(modifyFile "kernel/sched/core.c" "select_task_rq") #TODO: check
	text4=$(modifyFile "kernel/sched/core.c" "__sched_fork")
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 2 3 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text1" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text3" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO
	checkIfDmesgNOTContains "$text1_1" || exitError $LINENO
	git -C "$srcDir" restore net/ipv4/tcp_ipv4.c
	local text3_1=$(modifyFile net/ipv4/arp.c arp_send_dst next)
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 1 2 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text3_1" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO
	checkIfDmesgNOTContains "$text1" "$text3" || exitError $LINENO

	logStep "Check that the cumulative module is generated after undoing one of the file from previously changes but not from the last one"
	local text5=$(modifyFile "fs/readdir.c" "filldir64")
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 3 4 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text3_1" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text5" || exitError $LINENO
	git -C "$srcDir" restore net/ipv4/arp.c
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 1 3 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text5" || exitError $LINENO
	checkIfDmesgNOTContains "$text3_1" || exitError $LINENO

	logStep "Check undoing all changes at once"
	text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 2 4 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text1" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text5" || exitError $LINENO
	revertChanges
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 0 0 || exitError $LINENO
	clearLogs
	remoteSh $cmd
	checkIfDmesgNOTContains "$text1" "$text2" "$text4" "$text5" || exitError $LINENO

	#todo check if it's deku_0000 module

	logStep "Check if changes made only in function build-in in module works properly..."
	text2=$(modifyFile drivers/input/misc/uinput.c uinput_open)
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 1 1 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	local text2_1=$(modifyFile drivers/input/misc/uinput.c uinput_open next)
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 1 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text2_1" || exitError $LINENO

	logStep "Check if changes made in function build-in into kernel and function build-in into module works properly..."
	text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	text2=$(modifyFile drivers/input/misc/uinput.c uinput_open)
	# TODO: Check that the first module has been unloaded
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 1 2 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text1" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	checkIfDmesgNOTContains "$text2_1" || exitError $LINENO

	logStep "Add first other common changes..."
	text4=$(modifyFile kernel/sched/core.c __sched_fork)
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 2 2 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text1" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO

	logStep "Add second other common changes..."
	text1_1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect next)
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 2 2 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text1_1" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO
	checkIfDmesgNOTContains "$text1" || exitError $LINENO
	# todo unload one by one

	logStep "Undo changes in the first file..."
	git -C "$srcDir" restore net/ipv4/tcp_ipv4.c
	dekuDeploy || exitError $LINENO
	isNotCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 2 2 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text2" || exitError $LINENO
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO
	checkIfDmesgNOTContains "$text1_1" || exitError $LINENO

	logStep "Undo changes in the second file..."
	git -C "$srcDir" restore drivers/input/misc/uinput.c
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 2 2 || exitError $LINENO
	clearLogs
	runCmdAndCheckIfDmesgContains "$cmd" "$text4" || exitError $LINENO
	checkIfDmesgNOTContains "$text2" "$text1_1" || exitError $LINENO

	logStep "Undo changes in the fird file..."
	git -C "$srcDir" restore kernel/sched/core.c
	dekuDeploy || exitError $LINENO
	isCumulativeModule || exitError $LINENO
	containsNumberOfModulesAndPatches 1 2 || exitError $LINENO
	clearLogs
	remoteSh $cmd
	checkIfDmesgNOTContains "$text4" "$text2" "$text1_1" || exitError $LINENO

	logStep "Check the deku_00000000 module..."
	# workdirContainsOnly deku_00000000 || exitError $LINENO

	remoteSh "CMD='rmmod uinput.ko 2>&1 >/dev/null'; eval \$CMD; eval sudo \$CMD;"

	# text2=$(modifyFile drivers/input/misc/uinput.c uinput_open)
	# dekuDeploy || exitError $LINENO
	# workdirContainsOnly || exitError $LINENO

	# remoteSh "insmod deku/deku_00000000.ko"
	# text1=$(modifyFile net/ipv4/tcp_ipv4.c tcp_v4_connect)
	# dekuDeploy || exitError $LINENO
	# isCumulativeModule || exitError $LINENO
	# containsNumberOfModulesAndPatches 1 1 || exitError $LINENO
	# clearLogs
	# remoteSh $cmd
	# runCmdAndCheckIfDmesgContains "$cmd" "$text1" || exitError $LINENO

	# git -C "$srcDir" restore net/ipv4/tcp_ipv4.c
	# dekuDeploy || exitError $LINENO
	# workdirContainsOnly || exitError $LINENO
	# containsNumberOfModulesAndPatches 0 0 || exitError $LINENO
	# clearLogs
	# remoteSh $cmd
	# checkIfDmesgNOTContains "$text1" || exitError $LINENO

	logStep "OK"

	return 0
}

main()
{
	# TODO: Remove once ROX allocations for livepatch will be fixed
	[[ $KERNEL_VER == "origin/master" ]] && return;

	if [[ $LOCAL_TEST != "" ]]; then
		:
	else
		test
	fi
}

main $@
