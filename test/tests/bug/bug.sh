#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test whether BUG() works

FILES="fs/open.c"
DESCRIPTION="BUG()"
. test/common.sh

check()
{
	local text="$1"
	local srcDir=$(sourceDir $KERNEL_VERSION)

	logStep "Clear from previous test"
	revertChanges

	dekuDeploy || exitError 2
	clearLogs
	sleep 1
	remoteSh "rm -f /tmp/a; touch /tmp/a; chmod 644 /tmp/a"
	sleep 1

	if [[ $text == *"BUG"* ]]; then
		checkIfDmesgNOTContains "] kernel BUG at fs/open.c" || exitError 3
	fi

	if [[ $text == *"WARN"* ]]; then
		checkIfDmesgNOTContains "] WARNING: CPU: " || exitError 4
	fi
	checkIfDmesgNOTContains "Comm: chmod Tainted" || exitError 5

	logStep "Check "$text
	appendToFunction "$srcDir/fs/open.c" "chmod_common" "$text"

	clearLogs
	dekuDeploy || exitError 6
	sleep 1
	remoteSh "rm -f /tmp/a; touch /tmp/a; chmod 644 /tmp/a"
	sleep 1

	if [[ $text == *"BUG"* ]]; then
		checkIfDmesgContains "] kernel BUG at fs/open.c" || exitError 7
	fi

	if [[ $text == *"WARN"* ]]; then
		checkIfDmesgContains "] WARNING: CPU: " || exitError 8
	fi
}

test()
{
	remoteSh "CMD='sysctl -w kernel.panic_on_oops=0 2>&1 >/dev/null'; eval \$CMD; eval sudo \$CMD;"

	if [[ $VM_TEST == "" && $LOCAL_TEST == ""  ]]; then
		check "BUG();"
		check "BUG_ON(1);"
	fi
	check "__WARN();"
	check "WARN(1, \"test\");"
	check "WARN_ON(1);"
	check "WARN_ON_ONCE(1);"

	check "__WARN();WARN(1, \"test\");WARN_ON(1);WARN_ON_ONCE(1);"
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
