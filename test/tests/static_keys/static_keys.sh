#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# A test case to check if static keys are properly handled

FILES="net/ipv4/tcp_ipv4.c net/ipv4/udp.c net/ipv4/tcp_fastopen.c"
DESCRIPTION="Static keys"
. test/common.sh

insertOnLine()
{
    local file=$1
    local lineNo=$2
    local text=$3

    local pre=$(head -n $lineNo $file)
    local post=$(tail -n +$((lineNo+1)) $file)

    echo "$pre
$text
$post" > $file
}

addStaticKeysCode()
{
	local file="$srcDir/net/ipv4/tcp_ipv4.c"

	local textDefineStaticKeyTrue='DEFINE_STATIC_KEY_TRUE(statickey_test);'
	local textStaticBranch='
		if (static_branch_unlikely(&statickey_test)) {
			pr_info("After change key: %d.%d.%d.%d", daddr & 0xFF,
			daddr >> 8 & 0xFF, daddr >> 16 & 0xFF,
			daddr >> 24 & 0xFF);
		} else {
			pr_info("Before change key: %d.%d.%d.%d", daddr & 0xFF,
			daddr >> 8 & 0xFF, daddr >> 16 & 0xFF,
			daddr >> 24 & 0xFF);
		}
	'
	local textStaticBranchEnable='
		if ((daddr & 0xFF) == 192 && (daddr >> 8 & 0xFF) == 168 && \
			(daddr >> 16 & 0xFF) == 0 && (daddr >> 24 & 0xFF) == 1) {
				pr_info("Before switching static: %d", static_key_enabled(&statickey_test));
				static_branch_disable(&statickey_test);
				pr_info("After switching static: %d", static_key_enabled(&statickey_test));
			}
	'

	lineNo=$(grep -n "int tcp_v4_connect(struct sock" $file| cut -d : -f 1)
	insertOnLine $file $((lineNo-1)) "$textDefineStaticKeyTrue"
	lineNo=$(grep -n "nexthop = daddr = usin->sin_addr.s_addr;" $file| cut -d : -f 1)
	insertOnLine $file $lineNo "$textStaticBranch"
	lineNo=$(grep -n "orig_sport = inet->inet_sport;" $file| cut -d : -f 1)
	insertOnLine $file $((lineNo-1)) "$textStaticBranchEnable"
}

addStaticCall()
{
	local file="$srcDir/net/ipv4/tcp_fastopen.c"

	local textDefineStaticCall='DEFINE_STATIC_CALL(staticcall_key, func_a);'
	local textFuncs='
		#include <linux/static_call.h>
		int func_a(int arg1, int arg2);
		int func_b(int arg1, int arg2);
		int func_a(int arg1, int arg2) {
			pr_info("Call func_a/%s arg1:%d arg:2:%d", __func__, arg1, arg2);
			return 0;
		}
  		int func_b(int arg1, int arg2) {
			pr_info("Call func_b/%s arg1:%d arg:2:%d", __func__, arg1, arg2);
			return 0;
		}
	'
	local textCallAndSwitchCall='
		pr_info("DEKU %s test", __func__);
		static_call(staticcall_key)(0, 1);
		static_call_update(staticcall_key, func_b);
	'
	appendBeforeFunction "$file" tcp_fastopen_defer_connect "$textFuncs" > /dev/null
	appendBeforeFunction "$file" tcp_fastopen_defer_connect "$textDefineStaticCall" > /dev/null
	appendToFunction "$file" tcp_fastopen_defer_connect "$textCallAndSwitchCall" > /dev/null
}

test()
{
	local text="pr_info(\"testStaticKeys\");"
	local cmd="wget --timeout=1 --tries=3 192.168.0.1 2>/dev/null"
	local srcDir=$SOURCE_DIR
	local file="$srcDir/net/ipv4/tcp_ipv4.c"

	prepareKernelAndDeploy $KERNEL_VER || exitError 1
	runQemu

	logStep "Add code that contains static keys usage"
	addStaticKeysCode

	dekuDeploy -v || exitError 2
	remoteSh $cmd

	checkIfDmesgContains "Before change key" || exitError 3
	checkIfDmesgContains "After change key" || exitError 4

	logStep "Modify code wrapped with previously static keys"
	sed -i "s/After change key/AfterX change key/g" "$file"
	sed -i "s/Before change key/BeforeX change key/g" "$file"
	dekuDeploy || exitError 5
	remoteSh $cmd

	# checkIfDmesgNOTContains "BeforeX change key" || exitError 6 # uncomment if supported for migration static keys will be done
	checkIfDmesgContains "AfterX change key" || exitError 7

	logStep "Modify code wrapped with built-in static keys"
	sed -i 's/DEFINE_STATIC_KEY_TRUE(statickey_test);/DEFINE_STATIC_KEY_FALSE(statickey_test);/g' "$file"
	sed -i 's/static_branch_disable(\&statickey_test);/static_branch_enable(\&statickey_test);/g' "$file"
	buildKernelToLaunch || exitDirtyError 8
	runQemu

	remoteSh $cmd
	checkIfDmesgContains "BeforeX change key" || exitDirtyError 9
	checkIfDmesgContains "AfterX change key" || exitDirtyError 10

	sed -i "s/AfterX change key/After change key/g" "$file"
	sed -i "s/BeforeX change key/Before change key/g" "$file"
	if [[ $KERNEL_VERSION != v5.10.* && $KERNEL_VERSION != v5.15* ]]; then
		# TODO: probably value for static key is not set to the previous one on module load
		dekuDeploy || exitDirtyError 11
		remoteSh $cmd
		# checkIfDmesgNOTContains "Before change key" || exitDirtyError 12
		checkIfDmesgContains "After change key" || exitDirtyError 13 # uncomment if supported for migration static keys will be done
	fi

	logStep "Revert conditions and modify code wrapped with built-in static keys"
	sed -i 's/DEFINE_STATIC_KEY_FALSE(statickey_test);/DEFINE_STATIC_KEY_TRUE(statickey_test);/g' "$file"
	sed -i 's/static_branch_enable(\&statickey_test);/static_branch_disable(\&statickey_test);/g' "$file"

	addStaticCall

	buildKernelToLaunch || exitDirtyError 14
	runQemu

	remoteSh $cmd
	checkIfDmesgContains "Before change key" "After change key" "Call func_a/func_a" "Call func_b/func_b" || exitError 15

	sed -i "s/After change key/AfterX change key/g" "$file"
	sed -i "s/Before change key/BeforeX change key/g" "$file"
	dekuDeploy || exitDirtyError 16
	remoteSh $cmd
	# checkIfDmesgNOTContains "BeforeX change key" || exitDirtyError 17 # uncomment if supported for migration static keys will be done
	checkIfDmesgContains "AfterX change key" || exitDirtyError 18

	logStep "Modify function with static keys"
	appendToFunction "$srcDir/net/ipv4/udp.c" udp_destroy_sock "$text"
	clearLogs
	dekuDeploy || exitDirtyError 19
	for i in $(seq 1 20); do
		remoteSh 'echo test > /dev/udp/8.8.8.8/8000 || echo test | nc -u -w1 8.8.8.8 8000' 2>/dev/null
		checkIfDmesgContains "testStaticKeys" 1>/dev/null 2>/dev/null && break
	done
	checkIfDmesgContains "testStaticKeys" || exitDirtyError 20

	exitDirtyError 0
}

main()
{
	[[ $ANDROID ]] && return
	test
}

main $@
