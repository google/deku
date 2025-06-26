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
	local srcDir=$(sourceDir $KERNEL_VER)
	local ofile="$WORKDIR/patch_e9fa88a1_tcp_ipv4/patch.o"

	appendToFunction "$srcDir/$file" "tcp_req_err" "printk(KERN_INFO \"[$SCRIPT_NAME] DEKU tcp_req_err test\");"
	appendToFunction "$srcDir/$file" "tcp_v4_md5_lookup" "printk(KERN_INFO \"[$SCRIPT_NAME] DEKU tcp_v4_md5_lookup test\");"

	out=$(dekuBuild --log -v) || exitError 1

	readelf -a -W "$ofile" >> $LOG_FILE
	grep "Modified function:" <<< $out | while read line
	do
		line=${line#"Modified function: "}
		readelf -s -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/tcp_ipv4.o" | grep "\b$line$" >> $LOG_FILE
	done
	echo "Origin file:" >> $LOG_FILE
	readelf -r "$WORKDIR/patch_e9fa88a1_tcp_ipv4/tcp_ipv4.o" | grep .rela\_\_bug_table -B 0 -A 100 | awk -v RS= 'NR==1' >> $LOG_FILE
	readelf -r "$WORKDIR/patch_e9fa88a1_tcp_ipv4/tcp_ipv4.o" | grep .rela\_\_jump_table -B 0 -A 100 | awk -v RS= 'NR==1' >> $LOG_FILE

	if [[ $CHROMEOS ]]; then
		if [[ $KERNEL_VER == "v5.10" ]]; then
			readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError
			readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" | grep -q "contains 3 entries:" || exitError
		elif [[ $KERNEL_VER == "v5.15" ]]; then
			readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError
			readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" | grep -q "contains 3 entries:" || exitError
		elif [[ $KERNEL_VER == "v6.1" ]]; then
			readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError
			readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" | grep -q "contains 3 entries:" || exitError
		elif [[ $KERNEL_VER == "v6.6" ]]; then
			readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError
			readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" | grep -q "contains 3 entries:" || exitError
		elif [[ $KERNEL_VER == "v6.12" ]]; then
			readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" && exitError
			readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" && exitError
		fi
		# if [[ $KERNEL_VER == "v5.10" || $KERNEL_VER == "v6.12" ]]; then
		# 	logInfo $(grep "A close jump to a neighboring function with a jump of less than 4 bytes was detected (tcp_req_err -> reqsk_put)" <<< "$out")
		# 	logInfo $(grep "The non-traceable function reqsk_put is (in)directly called from traceable function tcp_req_err" <<< "$out")
		# 	grep "A close jump to a neighboring function with a jump of less than 4 bytes was detected (tcp_req_err -> reqsk_put)" <<< "$out" || { logErr "Fail"; exit 2; }
		# 	grep "The non-traceable function reqsk_put is (in)directly called from traceable function tcp_req_err" <<< "$out" || { logErr "Fail"; exit 3; }
		# fi
	elif [[ $KERNEL_VER == v6.8 ]]; then
		readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError
		readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" && exitError
	elif [[ $KERNEL_VER == v6.11 || $KERNEL_VER == v6.12* || $KERNEL_VER == v6.14* ]]; then
		# readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError
		readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" && exitError
		readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" && exitError
	elif [[ $KERNEL_VER == v6.6.* ]]; then
		readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" | grep -q "contains 2 entries:" || exitError
		readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" | grep -q "contains 3 entries:" || exitError
	else
		readelf -a -W "$ofile" | grep "Relocation section '.rela__bug_table'" && exitError
		readelf -a -W "$ofile" | grep "Relocation section '.rela__jump_table'" | grep -q "contains 3 entries:" || exitError
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
