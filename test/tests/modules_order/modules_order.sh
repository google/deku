#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if modules are loaded and unloaded in the correct order. This test takes module dependencies
# into account

FILES="drivers/input/input-mt.c drivers/gpu/drm/drm_atomic_uapi.c"
DESCRIPTION="Modules order"
KERNEL=$KERNEL_VERSION_5_15
. test/common.sh

test()
{
	local file1="drivers/input/input-mt.c"
	local function1="input_mt_report_pointer_emulation"
	local functionHeader1="void input_mt_report_pointer_emulation"
	local file2="drivers/gpu/drm/drm_atomic_uapi.c"
	local function2="drm_atomic_plane_set_property"
	local functionHeader2="static int drm_atomic_plane_set_property"

	prepareKernel $KERNEL_VERSION_5_15
	runQemu

	appendToFunction "$SOURCE_DIR/$file1" $function1 "cursor_x = 1;\ncursor_y = 1;"
	appendToFunction "$SOURCE_DIR/$file2" $function2 "pr_info(\"cursor=%dx%d\", cursor_x, cursor_y);"
	sed -i "s/$functionHeader1/int cursor_x = 2;\nint cursor_y = 2;\n$functionHeader1/g" "$SOURCE_DIR/$file1"
	sed -i "s/$functionHeader2/extern int cursor_x;\nextern int cursor_y;\n$functionHeader2/g" "$SOURCE_DIR/$file2"

	dekuDeploy || exit 1

	logStep "Checking modules loading order..."
	grep "module=" "$WORKDIR/$DEKU_RELOAD_SCRIPT" | nl | grep "1.*input_mt$" || exit 2
	grep "module=" "$WORKDIR/$DEKU_RELOAD_SCRIPT" | nl | grep "2.*drm_atomic_uapi$" || exit 3

	git -C "$SOURCE_DIR" checkout $file1 2>/dev/null
	git -C "$SOURCE_DIR" checkout $file2 2>/dev/null

	appendToFunction "$SOURCE_DIR/$file1" $function1 "cursor_x = 1;\ncursor_y = 1;"
	appendToFunction "$SOURCE_DIR/$file2" $function2 "pr_info(\"cursor=%dx%d\", cursor_x, cursor_y);"
	sed -i "s/$functionHeader1/extern int cursor_x;\nextern int cursor_y;\n$functionHeader1/g" "$SOURCE_DIR/$file1"
	sed -i "s/$functionHeader2/int cursor_x = 2;\nint cursor_y = 2;\n$functionHeader2/g" "$SOURCE_DIR/$file2"

	dekuDeploy || exit 4

	logStep "Checking modules un/loading order..."
	grep "module=" "$WORKDIR/$DEKU_RELOAD_SCRIPT" | nl | grep "1.*drm_atomic_uapi$" || exit 5
	grep "module=" "$WORKDIR/$DEKU_RELOAD_SCRIPT" | nl | grep "2.*input_mt$" || exit 6
	grep "\$RMMOD deku_" "$WORKDIR/$DEKU_RELOAD_SCRIPT" | nl | grep "1.*drm_atomic_uapi$" || exit 7
	grep "\$RMMOD deku_" "$WORKDIR/$DEKU_RELOAD_SCRIPT" | nl | grep "2.*input_mt$" || exit 8

	logStep "Checking modules unloading order..."
	git -C "$SOURCE_DIR" checkout $file1 2>/dev/null
	git -C "$SOURCE_DIR" checkout $file2 2>/dev/null

	dekuDeploy || exit 9

	grep "\$RMMOD deku_" "$WORKDIR/$DEKU_RELOAD_SCRIPT" | nl | grep "1.*input_mt$" || exit 10
	grep "\$RMMOD deku_" "$WORKDIR/$DEKU_RELOAD_SCRIPT" | nl | grep "2.*drm_atomic_uapi$" || exit 11

	logStep "OK"

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
