#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check that the found index for the symbols is correctly selected

FILES="net/ipv4/arp.c net/ipv4/tcp_ipv4.c net/ethernet/eth.c fs/open.c fs/readdir.c mm/mmap.c mm/vma.c"
DESCRIPTION="Symbol index"
. test/common.sh

modifyFunction()
{
	local file=$1
	local function=$2
	local text=$3
	local index=$4
	local srcDir=$(sourceDir $KERNEL_VERSION)

    sed -i "1s/^/static unsigned long long DEKU_TEST_INDEX = ${index}000000000;\n/" "$srcDir/$file"
	appendToFunction "$srcDir/$file" \
					 "$function" \
					 "printk(KERN_INFO \"[$SCRIPT_NAME] $text (%s): %llu\", __func__, DEKU_TEST_INDEX++);"
}

files=()
functions=()
cmds=()

addTest()
{
	files+=($1)
	functions+=($2)
	cmds+=("$3")
}

checkFunCall()
{
	local fun="$1"
	local cmd="$2"
	local text="$3"
	for x in $(seq 1 10);
	do
		remoteSh "$cmd"
		remoteSh "dmesg | grep -F \"$text\""
		res=$?
		[[ $res == 0 ]] && { echo "$REMOTE_OUT" >> $LOG_FILE; return 0; }
		echo "[$x] Try to find log from call $fun" >> $LOG_FILE
	done

	return 1
}

test()
{
	addTest "net/ipv4/arp.c" "arp_create" "CMD='ip -s -s neigh flush all 2>&1 >/dev/null'; eval \$CMD; eval sudo \$CMD; wget -q --spider google.com"
	addTest "net/ipv4/tcp_ipv4.c" "tcp_v4_connect" "CMD='ip -s -s neigh flush all 2>&1 >/dev/null'; eval \$CMD; eval sudo \$CMD; wget -q --spider google.com"
	addTest "fs/open.c" "chmod_common" "rm -f /tmp/a; touch /tmp/a; chmod 644 /tmp/a"
	addTest "fs/readdir.c" "filldir64" "sleep 2"
	if [[ $KERNEL_VERSION == v6.14* || $KERNEL_VERSION == v6.16* ]]; then
		addTest "mm/vma.c" "mmap_region" "sleep 2"
	else
		[[ $VM_TEST == "" ]] && addTest "mm/mmap.c" "mmap_region" "sleep 2"
	fi

	local count=${#files[@]}
	for (( i=0; i<count; i++ ))
	do
		modifyFunction ${files[$i]} ${functions[$i]} "DEKU_TEST_INDEX" $((i+1))
	done

	buildKernelToLaunch || exitDirtyError 1

	revertChanges

	for (( i=0; i<count; i++ ))
	do
		modifyFunction ${files[$i]} ${functions[$i]} "xDEKU_TEST_INDEX" $((i+1))
	done

	runQemu

	clearLogs
	dekuDeploy -v || exitDirtyError 2

	for i in $(eval echo "{0..$((count-1))}")
	do
		local func=${functions[$i]}
		text="xDEKU_TEST_INDEX ($func): $((i+1))00"
		checkFunCall $func "${cmds[$i]}" "$text"
		[[ $? != 0 ]] && logErr "Failed to find log from call $func" && exitDirtyError 3
		logInfo "Found \"$text\" in demsg"
	done

	logStep -n "Checking if symbols are relocated... "
	find "$WORKDIR/" -name "*.ko" -type f -exec nm -s "{}" \; >> $LOG_FILE
	local indexes=`
	find "$WORKDIR/" -name "*.ko" -type f -exec nm -s "{}" \; | \
	grep "A .klp.sym.vmlinux.DEKU_TEST_INDEX," | \
	cut -d, -f2 | \
	sort -h`

	local expected=`seq $count`

	if [[ "$expected" != "$indexes" ]];
	then
		logErr "Expected:\n$expected"
		logErr "Got:\n$indexes"
		logErr "Fail!"
		exitDirtyError 4
	fi

	logStep "OK"

	exitDirtyError 0
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
