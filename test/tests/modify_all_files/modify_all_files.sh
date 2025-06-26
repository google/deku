#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test that changes all functions in files and buld livepatch modules

FILES="*"
DESCRIPTION="Modify all files"
. test/common.sh

TAGS=test/tags/tags

modifyAllFunctionsAtOnce()
{
	local text="[$SCRIPT_NAME] DEKU $function test"
	local srcDir=$(sourceDir $KERNEL_VER)
#prepareKernelAndBuild
	revertChanges

	local dir=$srcDir/drivers/
	local files=$(find "$dir" -type f -name "*.c" | sed 's/\\n/\n/g')
	echo "$files"
	for file in $files; do
		$TAGS mod_funcs -2 $file "printk(KERN_INFO \"$text\");"
		dekuBuild || "Error $file"
		git -C $srcDir restore "*.c"
	done

	return 1
}

test()
{
	modifyAllFunctionsAtOnce
}

main()
{
	test
}

main $@
