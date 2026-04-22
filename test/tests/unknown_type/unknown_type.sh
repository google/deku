#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check if symbols with unknown type support relocations

FILES="net/sunrpc/svc.c"
DESCRIPTION="Relocate unknown type"
. test/common.sh

checkUnknowSymbolType()
{
	local file=$1
	local function=$2
	local text="DEKU $function test"
	local srcDir=$SOURCE_DIR

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"$text\");"

	clearLogs
	dekuBuild || exit 1
	local obj=$(cat $WORKDIR/patch_*/obj)
	obj=$(filenameNoExt "$obj")
	local koFile=$(find $WORKDIR -name "deku_*.ko")
	readelf -s -W "$koFile" >> $LOG_FILE
	readelf -s -W "$koFile" | grep -e ".klp.sym.$obj.rpcb_create_local,0" | grep -q NOTYPE || exitError

	logStep "OK"
}

test()
{
	checkUnknowSymbolType "net/sunrpc/svc.c" "svc_rpcb_setup"
}

main()
{
	[[ $ANDROID ]] && return
	test
}

findSymbolToTest()
{
	readelf -s -W $BUILD_DIR/vmlinux | grep FUNC | grep LOCAL > /tmp/a
	find $BUILD_DIR -name "*.o" -exec readelf -s -W {} \; | grep UND | awk '{print $8}' > /tmp/b
	grep -o -F -f /tmp/b /tmp/a | uniq -u
}

main $@
