#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check if __tracepoint_str and __trace_printk_fmt sections are copied into deku
# module

FILES="kernel/power/suspend.c"
DESCRIPTION="Copy tracepoint_str"
KERNEL=$KERNEL_VERSION_5_15
. test/common.sh

checkTracepointString()
{
	local file=$1
	local function=$2
	local srcDir=$SOURCE_DIR

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"\");"

	dekuBuild || exitError 1
	local koFile=$(find $WORKDIR -name "deku_*.ko")
	readelf -s -W "$koFile" >> $LOG_FILE
	if [[ $CHROMEOS ]]; then
		readelf -s -W "$koFile" | grep -q "s2idle_enter.___tp_str" || { logErr "Fail"; exitError 2; }
	fi
	readelf -s -W "$koFile" | grep -e "__tracepoint_str" | grep -q "SECTION LOCAL" || { logErr "Fail"; exitError 3; }
	readelf -s -W "$koFile" | grep -q "__tracepoint_suspend_resume" || { logErr "Fail"; exitError 4; }
}

test()
{
	checkTracepointString "kernel/power/suspend.c" "suspend_devices_and_enter"
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
