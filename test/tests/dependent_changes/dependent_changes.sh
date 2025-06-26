#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test the case where changes are made to two files and changes in second file
# depend on changes in first.

FILES="drivers/input/input-mt.c drivers/gpu/drm/drm_atomic_uapi.c fs/proc/cmdline.c"
DESCRIPTION="Dependent changes acros files"
. test/common.sh

test()
{
	local file1="drivers/input/input-mt.c"
	local function1="input_mt_report_pointer_emulation"
	local functionHeader1="void input_mt_report_pointer_emulation"
	local file2="drivers/gpu/drm/drm_atomic_uapi.c"
	local function2="drm_atomic_plane_set_property"
	local functionHeader2="static int drm_atomic_plane_set_property"
	local file3="fs/proc/cmdline.c"
	local function3="cmdline_proc_show"
	local functionHeader3="static int cmdline_proc_show"

	local srcDir=$(sourceDir $KERNEL_VERSION)

	logStep "Make dependent changes..."
	appendToFunction "$srcDir/$file1" $function1 "cursor_x = 1;\ncursor_y = 1;"
	appendToFunction "$srcDir/$file2" $function2 "pr_info(\"cursor=%dx%d\", cursor_x, cursor_y);"
	#TODO: use before function
	sed -i "s/$functionHeader1/int cursor_x = 2;\nint cursor_y = 2;\n$functionHeader1/g" "$srcDir/$file1"
	sed -i "s/$functionHeader2/extern int cursor_x;\nextern int cursor_y;\n$functionHeader2/g" "$srcDir/$file2"

	dekuDeploy || exitError 1

	logStep "Test reverse dependent changes..."
	git -C "$srcDir" checkout $file1 2>/dev/null
	git -C "$srcDir" checkout $file2 2>/dev/null

	appendToFunction "$srcDir/$file1" $function1 "cursor_x = 1;\ncursor_y = 1;"
	appendToFunction "$srcDir/$file2" $function2 "pr_info(\"cursor=%dx%d\", cursor_x, cursor_y);"
	sed -i "s/$functionHeader1/extern int cursor_x;\nextern int cursor_y;\n$functionHeader1/g" "$srcDir/$file1"
	sed -i "s/$functionHeader2/int cursor_x = 2;\nint cursor_y = 2;\n$functionHeader2/g" "$srcDir/$file2"

	dekuDeploy || exitError 2

	logStep "Check if changes are applied..."

	appendToFunction "$srcDir/$file3" $function3 "pr_info(\"cursor=%dx%d\", cursor_x, cursor_y);"
	sed -i "s/$functionHeader3/extern int cursor_x;\nextern int cursor_y;\n$functionHeader3/g" "$srcDir/$file3"

	dekuDeploy || exitError 3
	runCmdAndCheckIfDmesgContains "cat /proc/cmdline" "cursor=2x2" || exitError 4

	logStep "OK"

	return 0
}

main()
{
	test
}

main $@
