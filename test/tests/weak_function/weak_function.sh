#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check if a weak function is not overridden by DEKU when other function with
# the same name exists. The weak function can be replaced only if there is no
# other implementation of this function.

FILES="net/ipv4/tcp_ipv4.c arch/x86/kernel/itmt.c"
DESCRIPTION="Weak function"
. test/common.sh

test()
{
	local srcDir=$(sourceDir $KERNEL_VERSION)

	appendBeforeFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect 'void weak_fun(void);\n\nvoid __weak weak_fun(void){printk(KERN_INFO "weak function called from %s", __FILE__);}'
	appendBeforeFunction "$srcDir/arch/x86/kernel/itmt.c" sched_set_itmt_core_prio 'void weak_fun(void);\n\nvoid weak_fun(void){printk(KERN_INFO "weak function called from %s", __FILE__);}'
	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect "weak_fun();"

	buildKernelToLaunch || exitDirtyError 1
	runQemu

	logStep "Check if the local weak function is not called after change the caller function"
	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect "printk(KERN_INFO \"$text\");"

	dekuDeploy || exitDirtyError 2
	clearLogs
	remoteSh "wget -q --spider google.com"
	checkIfDmesgContains "weak function called from arch/x86/kernel/itmt.c" || exitDirtyError 3

	logStep "Check if weak function is not called after change it's implementation"
	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" weak_fun "printk(KERN_INFO \"Modified weak function\");"

	out=$(dekuDeploy --stdout) || exitDirtyError 4
	grep -q "The 'weak_fun' is a weak function and other implementation is provided in the kernel. Skip it." <<< "$out" || echo "$out" || exitError 5

	clearLogs
	remoteSh "wget -q --spider google.com"
	checkIfDmesgContains "weak function called from arch/x86/kernel/itmt.c" || exitDirtyError 6

	logStep "Check if weak function is replaced if there is no other implementation"

	revertChanges

	appendBeforeFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect 'void weak_fun(void);\n\nvoid __weak weak_fun(void){printk(KERN_INFO "weak function called from %s", __FILE__);}'
	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect "weak_fun();"

	buildKernelToLaunch || exitDirtyError 7
	runQemu

	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" weak_fun "printk(KERN_INFO \"Modified weak function\");"

	dekuDeploy || exitDirtyError 8
	clearLogs
	remoteSh "wget -q --spider google.com"
	checkIfDmesgContains "Modified weak function" || exitDirtyError 9

	exitDirtyError 0
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
