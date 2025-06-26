#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check if build will pass after correcting errors in the source code.

FILES="drivers/gpu/drm/drm_mm.c"
DESCRIPTION="Build after fixing errors"
. test/common.sh

checkBuild()
{
	local file="drivers/gpu/drm/drm_mm.c"
	local srcDir=$(sourceDir $KERNEL_VER)

	appendToFunction "$srcDir/$file" add_hole "pr_info(\"test\");"

	dekuBuild || { logErr "Fail"; exit 1; }

	appendToFunction "$srcDir/$file" rm_hole "}"

	logStep -n "Build deku module with errors in $file... "
	dekuBuild && { logErr "Fail"; exit 2; }
	logStep "OK"

	git -C "$srcDir" checkout $file 2>/dev/null

	appendToFunction "$srcDir/$file" add_hole "pr_info(\"test 1\");"
	appendToFunction "$srcDir/$file" rm_hole "pr_info(\"test 2\");"

	logStep -n "Build deku module after fix errors in $file... "
	dekuBuild || { logErr "Fail"; exit 3; }
	logStep "OK"
}

test()
{
	checkBuild
}

main()
{
	test
}

main $@
