#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Testing if a local symbol that has a global variation is correctly detected

FILES="net/ipv4/route.c"
DESCRIPTION="Static and global symbol"
. test/common.sh

checkLocalSymbol()
{
	local file="net/ipv4/route.c"
	local function="ipv4_blackhole_route"
	local srcDir=$(sourceDir $KERNEL_VER)

	[[ $KERNEL_VER == v5.10 ]] && return

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"DEKU\");"

	dekuBuild || exitError 1
	local koFile=$(find $WORKDIR -name "deku_*.ko")
	logStep -n "Local symbol is marked as a '.klp.sym.'... "
	readelf -s -W "$koFile" >> $LOG_FILE
	if [[ $KERNEL_VER == v6.1 || $KERNEL_VER == v6.12 ]]; then
		readelf -s -W "$koFile" | grep -q ".klp.sym.vmlinux.dst_discard,1"  || { logErr "Fail"; exitError 2; }
	else
		readelf -s -W "$koFile" | grep -q ".klp.sym.vmlinux.dst_discard,2"  || { logErr "Fail"; exitError 2; }
	fi
	logStep "OK"
}

test()
{
	checkLocalSymbol
}

main()
{
	if [[ $CHROMEOS ]]; then
		return
	fi

	test
}

main $@
