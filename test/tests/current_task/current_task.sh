#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if changed functions that uses the `current_task` variable works properly

FILES="fs/readdir.c"
DESCRIPTION="Current task"
. test/common.sh

checkCall()
{
	local file=$1
	local function=$2
	local cmd=$3
	local text=$4

	if [[ "$testmodify" != "nomodify" ]]; then
		appendToFunction "$SOURCE_DIR/$file" $function "printk(KERN_INFO \"$text\\\n\");"
	fi

	clearLogs
	dekuDeploy || exitError 2
	sleep 1
	remoteSh $cmd
	sleep 1
	checkIfDmesgContains "$text" || exitError 3
}

test()
{
	local file=fs/readdir.c
	local function=filldir64
	local cmd="wget -q --spider google.com"

	logStep "Test modification..."
	checkCall "$file" $function "$cmd" "test1"

	echo -n "Test undo modifications and unload module..."

	logStep "OK"
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
