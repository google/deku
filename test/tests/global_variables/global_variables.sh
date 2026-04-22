#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if global variables are properly mapped and if new variables are detected

FILES="net/ipv4/tcp_ipv4.c"
DESCRIPTION="Global variables"
. test/common.sh

GlobalVars='
static int static_global_var0_1 = 0;
static int static_global_var0_2 = 0;
static int static_global_var1 = 1;
static int static_global_var2 = 2;
static int volatile static_volatile_global_var = 3;
static int const static_const_global_var = 4;

int global_var0_1 = 0;
int global_var0_2 = 0;
int global_var1 = 5;
int global_var2 = 6;
int volatile volatile_global_var = 7;
int const const_global_var = 8;
'

FunctionCode='
static_global_var0_1 += 19;
static_global_var0_2 += 23;
static_global_var1 += 1000;
static_global_var2 += 1000;
static_volatile_global_var += 1000;

global_var0_1 += 17;
global_var0_2 += 13;
global_var1 += 1000;
global_var2 += 1000;
volatile_global_var += 1000;

pr_info("static_global_var0_1=%d
static_global_var0_2=%d
static_global_var1=%d
static_global_var2=%d
static_volatile_global_var=%d
static_const_global_var=%d
global_var0_1=%d
global_var0_2=%d
global_var1=%d
global_var2=%d
volatile_global_var=%d
const_global_var=%d
	",
	static_global_var0_1,
	static_global_var0_2,
	static_global_var1,
	static_global_var2,
	static_volatile_global_var,
	static_const_global_var,
	global_var0_1,
	global_var0_2,
	global_var1,
	global_var2,
	volatile_global_var,
	const_global_var
);
'

GlobalVarsReadMostly='
static int static_global_var_read_mostly __read_mostly = 0;
static int static_global_var_ro_after_init __ro_after_init = 0;
static int static_global_var_nosave __nosavedata = 0;
static int static_global_var_cacheline_aligned __cacheline_aligned = 0;
static int static_global_var_page_aligned __page_aligned_data = 0;
static int static_global_var_page_aligned_bss __page_aligned_bss = 0;
'
FunctionCodeReadMostly='
static_global_var_read_mostly += 19;
static_global_var_ro_after_init += 3;
static_global_var_nosave += 7;
static_global_var_cacheline_aligned += 11;
static_global_var_page_aligned += 13;
static_global_var_page_aligned_bss += 17;

pr_info("static_global_var_read_mostly=%d
static_global_var_ro_after_init=%d
static_global_var_nosave=%d
static_global_var_cacheline_aligned=%d
static_global_var_page_aligned=%d
static_global_var_page_aligned_bss=%d
	",
	static_global_var_read_mostly,
	static_global_var_ro_after_init,
	static_global_var_nosave,
	static_global_var_cacheline_aligned,
	static_global_var_page_aligned,
	static_global_var_page_aligned_bss
);'

test()
{
	local file="net/ipv4/tcp_ipv4.c"
	local function="tcp_v4_connect"
	local cmd="wget -q --spider google.com; wget -q --spider example.com"
	local srcDir=$SOURCE_DIR

	local expectedmsg=
	local altExpecteDmsg=
	local altExpecteDmsg2=
	expectedmsg="static_global_var0_1=76 static_global_var0_2=92 static_global_var1=4001 static_global_var2=4002 static_volatile_global_var=4003 static_const_global_var=4 global_var0_1=68 global_var0_2=52 global_var1=4005 global_var2=4006 volatile_global_var=4007 const_global_var=8"
	altExpecteDmsg="static_global_var0_1=551 static_global_var0_2=667 static_global_var1=29001 static_global_var2=29002 static_volatile_global_var=29003 static_const_global_var=4 global_var0_1=493 global_var0_2=377 global_var1=29005 global_var2=29006 volatile_global_var=29007 const_global_var=8"
	altExpecteDmsg2="static_global_var0_1=1007 static_global_var0_2=1219 static_global_var1=53001 static_global_var2=53002 static_volatile_global_var=53003 static_const_global_var=4 global_var0_1=901 global_var0_2=689 global_var1=53005 global_var2=53006 volatile_global_var=53007 const_global_var=8"

	logStep "Checking detection new global variables... "
	appendBeforeFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect "$GlobalVars"
	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect "$FunctionCode"

	clearLogs
	dekuDeploy || exitError 2
	remoteSh $cmd
	remoteSh $cmd
	checkIfDmesgContains "$expectedmsg" || exitError 3

	logStep "Checking if global variables are properly mapped"

	buildKernelToLaunch || exitDirtyError 4
	runQemu

	remoteSh $cmd

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"\");"
	clearLogs
	dekuDeploy || exitDirtyError 5
	sleep 1
	local excpectMsg=
	for i in {1..150}; do
		[[ "$excpectMsg" != "" ]] && break
		remoteSh $cmd
		sleep 0.5
		checkIfDmesgContains "$expectedmsg" > /dev/null 2>&1 && excpectMsg="$expectedmsg"
		checkIfDmesgContains "$altExpecteDmsg" > /dev/null 2>&1 && excpectMsg="$altExpecteDmsg"
		checkIfDmesgContains "$altExpecteDmsg2" > /dev/null 2>&1 && excpectMsg="$altExpecteDmsg2"
	done
	[[ "$excpectMsg" == "" ]] && excpectMsg="$expectedmsg"
	checkIfDmesgContains "$excpectMsg" || exitDirtyError 6

	logStep "OK"

	git -C "$srcDir" checkout $file 2>/dev/null

	appendBeforeFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect "$GlobalVarsReadMostly"
	appendToFunction "$srcDir/net/ipv4/tcp_ipv4.c" tcp_v4_connect "$FunctionCodeReadMostly"

	logStep -n "Remove all global variables and introduce new variables with extra annotations like __read_mostly... "
	dekuBuild || { echo "Fail"; exitDirtyError 7; }

	logStep "OK"
	exitDirtyError 0

	return 0
}

main()
{
	FunctionCode="${FunctionCode//$'\n'/ }"
	FunctionCodeReadMostly="${FunctionCodeReadMostly//$'\n'/ }"

	[[ $ANDROID ]] && return
	if [[ $LOCAL_TEST != "" ]]; then
		:
	else
		test
	fi
}

main $@
