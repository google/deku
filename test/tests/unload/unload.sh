#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test whether reverting changes in source files causes unload deku module

FILES="net/ipv4/tcp_ipv4.c fs/timerfd.c net/ipv4/arp.c"
DESCRIPTION="Unload"
. test/common.sh

checkCall()
{
	local file=$1
	local function=$2
	local cmd=$3
	local text=$4
	local testmodify=$5
	local srcDir=$(sourceDir $KERNEL_VER)

	if [[ "$testmodify" != "nomodify" ]]; then
		appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"$text\\\n\");"
	fi

	dekuDeploy || exitError 2
	clearLogs
	sleep 1
	remoteShOut $cmd
	sleep 1
	if [[ "$testmodify" == "nomodify" ]]; then
		checkIfDmesgNOTContains "$text" || exitError 3
	else
		checkIfDmesgContains "$text" || exitError 4
	fi
}

test()
{
	local file=net/ipv4/tcp_ipv4.c
	local function=tcp_v4_connect
	local cmd="wget -q --spider google.com"
	local srcDir=$(sourceDir $KERNEL_VER)

	logStep "Test first modification..."
	checkCall "$file" $function "$cmd" "[$SCRIPT_NAME] test1"

	logStep "Test second modification..."
	checkCall "$file" $function "$cmd" "[$SCRIPT_NAME] test2"

	appendToFunction "$srcDir/fs/timerfd.c" "timerfd_triggered" "printk(KERN_INFO \"DEKU\");"
	checkCall "net/ipv4/arp.c" "arp_create" "wget -q --spider google.com" "[$SCRIPT_NAME] test"
	local loadedmodules=`remoteShOut lsmod`
	if ! grep -q "deku_44982e17_arp" <<< "$loadedmodules"; then
		logErr "Fail"
		exitError 5
	fi
	if ! grep -q "deku_b8a2b8ef_timerfd" <<< "$loadedmodules"; then
		logErr "Fail"
		exitError 6
	fi
	if ! grep -q "deku_e9fa88a1_tcp_ipv4" <<< "$loadedmodules"; then
		logErr "Fail"
		exitError 7
	fi
	logStep "Test undo modifications and unload module..."
	git -C "$srcDir" checkout $file
	git -C "$srcDir" checkout "fs/timerfd.c"
	git -C "$srcDir" checkout "net/ipv4/arp.c"
	checkCall "$file" $function "$cmd" "[$SCRIPT_NAME] test2" "nomodify"

	if ! grep -q "\$RMMOD deku_e9fa88a1_tcp_ipv4" "$WORKDIR/$DEKU_RELOAD_SCRIPT"; then
		logErr "Fail"
		exitError 8
	fi

	sed -i "s/\$INSMOD deku\/$INSPECT_MODULE_NAME.ko//g" "$WORKDIR/$DEKU_RELOAD_SCRIPT"

	if grep -q "\$INSMOD" "$WORKDIR/$DEKU_RELOAD_SCRIPT"; then
		logErr "Fail"
		exitError 9
	fi
	loadedmodules=`remoteShOut lsmod`
	if grep -q "deku_44982e17_arp" <<< "$loadedmodules"; then
		logErr "Fail"
		exitError 10
	fi
	if grep -q "deku_b8a2b8ef_timerfd" <<< "$loadedmodules"; then
		logErr "Fail"
		exitError 11
	fi
	if grep -q "deku_e9fa88a1_tcp_ipv4" <<< "$loadedmodules"; then
		logErr "Fail"
		exitError 12
	fi

	logStep "OK"
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
