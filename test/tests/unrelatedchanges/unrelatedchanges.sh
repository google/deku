#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if unrelated changes are properly discarded

FILES="drivers/gpu/drm/i915/display/intel_cursor.c"
DESCRIPTION="Unrelated changes"
. test/common.sh

inlineTest()
{
	local file=$1
	local function=$2
	local text=$3
	local expectedfuncs=$4
	local discardedfuncs=$5
	local modname="$(generateModuleName $file)"
	local moduledir="$WORKDIR/$modname"
	local srcDir=$(sourceDir $KERNEL_VERSION)

	appendToFunction "$srcDir/$file" $function "$text"
	appendToFunction "$srcDir/$file" i9xx_update_cursor ";"

	dekuBuild || exit 1

	echo -n "Discard unrelated changes in $file... "
	for function in ${expectedfuncs//,/ }
	do
		if ! grep -q $function "$moduledir/$MOD_SYMBOLS_FILE"; then
			echo "Fail"
			logErr "Can't find the '$function' function in the $moduledir/$MOD_SYMBOLS_FILE file"
		fi
	done

	while read -r line
	do
		if ! grep -q $line <<< $expectedfuncs; then
			echo "Fail"
			logErr "Found unexpected function '$function' in the $moduledir/$MOD_SYMBOLS_FILE file"
		fi
	done < "$moduledir/$MOD_SYMBOLS_FILE"

	logStep "OK"
}

main()
{
	MAIN_PATH=`dirname "$0"`

	inlineTest "drivers/gpu/drm/i915/display/intel_cursor.c" "i9xx_check_cursor" "pr_info(\"%x\", intel_cursor_base(plane_state));" i9xx_check_cursor
}

main $@
