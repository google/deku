#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if changes made in text string are properly detected

FILES="net/ipv4/tcp_ipv4.c"
DESCRIPTION="String changed"
. test/common.sh

test()
{
	local file="net/ipv4/tcp_ipv4.c"
	local function="tcp_v4_connect"
	local text="${ScriptName}DEKUDEKUDEKUTEST"
	local newtext="${ScriptName}dekutestdeku"
	local srcDir=$(sourceDir $KERNEL_VER)

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"$text\");"

	buildKernel || exitError 1
	runQemu

	sed -i s/$text/$newtext/g "$srcDir/$file"

	clearLogs
	dekuDeploy || exitError 2
	remoteSh "wget -q --spider google.com"
	checkIfDmesgContains "$newtext" || exitError 3

	return 0
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
