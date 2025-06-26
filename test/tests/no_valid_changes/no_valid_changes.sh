#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test that checks if no valid changes are properly detected and checks if
# module does not try to be loaded

FILES="net/ipv4/tcp_ipv4.c"
DESCRIPTION="No valid changes"
. test/common.sh

checkNoValidChanges()
{
	local file=$1
	local validfunction=$2
	local novalidfunction=$3
	local srcDir=$(sourceDir $KERNEL_VER)

	appendToFunction "$srcDir/$file" $validfunction "printk(KERN_INFO \"[$SCRIPT_NAME] DEKU test\");"

	logStep -n "Checking if valid changes are properly detected... "
	out=$(dekuDeploy --log) || { logErr "Fail"; exit 1; }
	grep -q "Loading..." <<< "$out" || { logErr "Fail"; exit 2; }
	grep -q "Changes successfully applied!" <<< "$out" || { logErr "Fail"; exit 3; }
	logStep "OK"

	appendToFunction "$srcDir/$file" $novalidfunction "printk(KERN_INFO \"[$SCRIPT_NAME] DEKU test\");"

	logStep -n "Checking if no valid changes are properly detected... "
	out=$(dekuBuild --log) || { logErr "Fail"; exit 4; }
	logStep "OK"

	logStep "Check reverting changes... "
	git -C "$srcDir" checkout $file 2>/dev/null
	appendToFunction "$srcDir/$file" $novalidfunction "printk(KERN_INFO \"[$SCRIPT_NAME] DEKU test\");"
	out=$(dekuDeploy --log -v)
	local res=$?
	[[ $res != 0 ]] && { logErr "Failed with return code: $res"; exit 5; }
	grep -q "Reverting changes from $file" <<< "$out" || { logErr "Fail"; exit 6; }
	# grep -q "No valid changes detected since last run" <<< "$out" || { logErr "Fail"; exit 7; } #TODO: check if this is needed
	grep -q "Modules to unload: deku_.\+patch_e9fa88a1_tcp_ipv4" <<< "$out" || { logErr "Fail"; exit 8; }
	grep -q "Reverting..." <<< "$out" || { logErr "Fail"; exit 9; }
	grep -q "Changes successfully applied!" <<< "$out" || { logErr "Fail"; exit 10; }
	grep -q "^res=\$(\$INSMOD" "$WORKDIR/$DEKU_RELOAD_SCRIPT" || { logErr "Fail"; exit 11; }
	logStep "OK"

	return 0
}

test()
{
	checkNoValidChanges "net/ipv4/tcp_ipv4.c" "tcp_v4_connect" "tcp_v4_init"
}

main()
{
	test
}

main $@
