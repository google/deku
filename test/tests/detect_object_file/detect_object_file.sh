#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# A test case to check that a file that was enabled for compilation and then
# disabled is correctly detected.

FILES="drivers/input/misc/uinput.c"
DESCRIPTION="Detect object file"
. test/common.sh

checkDetectionObjectFile()
{
	local text="pr_info(\"test\");"
	local srcfile=drivers/input/misc/uinput.c
	local srcDir=$(sourceDir $KERNEL_VER)

	logStep "Check if basic generate module works"
	prepareKernelAndBuild $KERNEL_VER CONFIG_INPUT_UINPUT

	appendToFunction "$srcDir/$srcfile" uinput_open "$text"

	dekuBuild || exit 1
	local koFile=$(find $WORKDIR -name "deku_*.ko")
	[[ ! -f "$koFile" ]] && exit 2

	logStep "Check if DEKU module is not generated for kernel module if it's not enabled in kernel config"
	prepareKernelAndBuild $KERNEL_VER -CONFIG_INPUT_UINPUT

	appendToFunction "$srcDir/$srcfile" uinput_open "$text"

	dekuBuild -v || exit 3
	koFile=$(find $WORKDIR -name "deku_*.ko")
	[[ -f "$koFile" ]] && exit 4

	logStep "Check if DEKU module is generated for kernel module if it's enabled in kernel config"
	prepareKernelAndBuild $KERNEL_VER +CONFIG_INPUT_UINPUT

	appendToFunction "$srcDir/$srcfile" uinput_open "$text"

	dekuBuild || exit 5
	koFile=$(find $WORKDIR -name "deku_*.ko")
	[[ ! -f "$koFile" ]] && exit 6

	logStep "Check if DEKU module is not generated for kernel module after it's getting disabled in kernel config"
	prepareKernelAndBuild $KERNEL_VER -CONFIG_INPUT_UINPUT

	appendToFunction "$srcDir/$srcfile" uinput_open "$text"

	dekuBuild || exit 7
	koFile=$(find $WORKDIR -name "deku_*.ko")
	[[ -f "$koFile" ]] && exit 8

	out=$(dekuBuild --log)
	grep -q "No valid changes detected" <<< "$out" || { logErr "Fail"; exit 9; }

	logStep "OK"
}

test()
{
	checkDetectionObjectFile
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
