#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test whether BUG() works

FILES="fs/open.c"
DESCRIPTION="BUG()"
. test/common.sh

testExit()
{
	remoteSh reboot
	waitForSystemBootUp
	exitError $1
}

check()
{
	local text="$1"
	local srcDir=$SOURCE_DIR

	logStep "Clear from previous test"
	revertChanges

	dekuDeploy || exitError 2
	clearLogs
	sleep 1
	remoteSh "rm -f /tmp/a; touch /tmp/a; chmod 644 /tmp/a"
	sleep 1

	if [[ $text == *"BUG"* ]]; then
		checkIfDmesgNOTContains "] kernel BUG at fs/open.c" || testExit 3
	fi

	if [[ $text == *"WARN"* ]]; then
		checkIfDmesgNOTContains "] WARNING: CPU: " || testExit 4
	fi
	checkIfDmesgNOTContains "Comm: chmod Tainted" || testExit 5

	logStep "Check "$text
	appendToFunction "$srcDir/fs/open.c" "chmod_common" "$text"

	clearLogs
	dekuDeploy || testExit 6
	sleep 1
	remoteSh "rm -f /tmp/a; touch /tmp/a; chmod 644 /tmp/a"
	sleep 1

	if [[ "$KERNEL_VERSION" =~ ^v[0-9]+\.[0-9]+-rc[0-9]+$ ]]; then
		checkIfDmesgContains "] kernel BUG at fs/open.c" || testExit 7
	else
		if [[ $text == *"BUG"* ]]; then
			checkIfDmesgContains "] kernel BUG at fs/open.c" || testExit 8
		fi

		if [[ $text == *"WARN"* ]]; then
			checkIfDmesgContains "] WARNING: CPU: " || testExit 9
		fi
	fi
}

test()
{
	[[ $ANDROID ]] && return
	[[ $VM_TEST ]] && remoteSh "sudo sysctl -w kernel.panic_on_oops=0" || remoteSh "sysctl -w kernel.panic_on_oops=0"

	if [[ $VM_TEST == "" && $LOCAL_TEST == ""  ]]; then
		check "BUG();"
		check "BUG_ON(1);"
	fi
	check "__WARN();"
	check "WARN(1, \"test\");"
	check "WARN_ON(1);"
	check "WARN_ON_ONCE(1);"

	check "__WARN();WARN(1, \"test\");WARN_ON(1);WARN_ON_ONCE(1);"

	remoteSh reboot
	waitForSystemBootUp
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
