#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check if only needed symbols are copied

FILES="net/ipv4/tcp_ipv4.c"
DESCRIPTION="Filter symbols"
. test/common.sh

filterTest()
{
	local file="net/ipv4/tcp_ipv4.c"
	local text="[$SCRIPT_NAME] DEKU $function test"
	local srcDir=$(sourceDir $KERNEL_VER)

	appendToFunction "$srcDir/$file" "tcp_req_err" "printk(KERN_INFO \"$text\");"
	appendToFunction "$srcDir/$file" "tcp_v4_md5_lookup" "printk(KERN_INFO \"$text\");"

	dekuBuild || exitError 1

	readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" >> $LOG_FILE

	if [[ $KERNEL_VER == v6.8 ]]; then
		readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError 2
		readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__jump_table'" && exitError 3
	elif [[ $KERNEL_VER == v6.11 ]]; then
		# readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError 2
		readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__bug_table'" && exitError 2
		readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__jump_table'" && exitError 3
	elif [[ $KERNEL_VER == v5.10.* ]]; then
		readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__bug_table'" && exitError 2
		readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__jump_table'" | grep -q "contains 3 entries:" || exitError 3
	else
		readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 4 entries:" || exitError 4
		readelf -a -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o" | grep "Relocation section '.rela__jump_table'" | grep -q "contains 3 entries:" || exitError 5
	fi

	logInfo "OK"
}

test()
{
	filterTest
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
