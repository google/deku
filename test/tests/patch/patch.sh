#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if apply changes from patch file works

FILES="net/ipv4/tcp_output.c net/ethernet/eth.c include/net/arp.h include/net/mptcp.h"
DESCRIPTION="Use patch file"
. test/common.sh

test()
{
	local file="net/ipv4/tcp_output.c"
	local function="tcp_syn_options"
	local text="[$SCRIPT_NAME] DEKU patch $function test"
	local srcDir=$SOURCE_DIR
	local patchesDir=/tmp/deku_patches
	local localPatchesDir="$patchesDir"

	[[ $VM_TEST ]] && { patchesDir=/tmp/deku-vm-mount/deku_patches/; localPatchesDir=/home/\$USER/deku_patches/; }
	local patchFile="$patchesDir/deku_patch.diff"
	local localPatchFile="$localPatchesDir/deku_patch.diff"

	local downloadCmd="curl --silent --head unknown.com 2>&1 > /dev/null; curl --silent --head google.com 2>&1 > /dev/null; curl --silent --head google.eu 2>&1 > /dev/null; curl --silent --head bing.com 2>&1 > /dev/null;"
	downloadCmd+="wget --quiet --spider unknown.com 2>&1 > /dev/null; wget --quiet --spider google.com 2>&1 > /dev/null; wget --quiet --spider google.eu 2>&1 > /dev/null; wget --quiet --spider bing.com 2>&1 > /dev/null;"
		
	rm -rf $patchesDir
	mkdir -p $patchesDir

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"$text\");"
	git -C "$srcDir" diff -- $FILES ':(exclude)*.config' > "$patchFile"
	revertChanges

	out=$(dekuBuild --stdout -p "$localPatchFile") || echo "$out" || exitError 1
	grep -q "Livepatch module was built:" <<< "$out" || exitError 2

	# make sure that the kernel sources dir isn't patched
	grep -F "$text" "$srcDir/$file" && exitError 3
	grep -qF "$text" "$WORKDIR/patched_sources/$file" || exitError 4

	koFile=$(find $WORKDIR -name "deku_*.ko")
	[[ ! -f "$koFile" ]] && exitError 5

	grep -qw -e __tcp_transmit_skb -e tcp_syn_options "$(dirname $koFile)/livepatch.c" || exitError 6

	dekuDeploy -p "$localPatchFile" || exitError 7
	clearLogs
	remoteSh "$downloadCmd"
	checkIfDmesgContains "$text" || exitError 8

	# make sure that the kernel sources dir isn't patched
	grep -F "$text" "$srcDir/$file" && exitError 9
	grep -qF "$text" "$WORKDIR/patched_sources/$file" || exitError 10

	logStep "Test cleanup"
	dekuDeploy || exitError 11
	clearLogs
	remoteSh "$downloadCmd"
	checkIfDmesgNOTContains "$text" || exitError 12
	[[ -d "$WORKDIR/patched_sources" ]] && exitError 13

	logStep "Test multifiles patch"
	sed -i "s/struct seq_file;/extern int _deku_var_test;\nstruct seq_file;/g" "$srcDir/include/net/mptcp.h"
	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"${text}_1 %d\", _deku_var_test++);"
	appendBeforeFunction "$srcDir/net/ethernet/eth.c" eth_type_trans "int _deku_var_test = 0;"
	appendToFunction "$srcDir/net/ethernet/eth.c" eth_type_trans "printk(KERN_INFO \"%s_1 %d\", __func__, _deku_var_test++);"
	appendBeforeFunction "$srcDir/include/net/arp.h" __ipv4_confirm_neigh "extern int _deku_var_test;"
	git -C "$srcDir" diff -- $FILES ':(exclude)*.config' > "$patchFile"
	revertChanges
	if [[ ! $ANDROID ]]; then
	dekuDeploy -p "$localPatchFile" || { echo "err:$?";  exitError 14; }
	clearLogs
	remoteSh "ip -s -s neigh flush all; $downloadCmd"
	checkIfDmesgContains "${text}_1" || exitError 15
	checkIfDmesgContains "eth_type_trans_1" || exitError 16

	logStep "Test multi patches"
	rm $patchesDir/*
	sed -i "s/struct seq_file;/extern int _deku_var_test;\nstruct seq_file;/g" "$srcDir/include/net/mptcp.h"
	git -C "$srcDir" diff -- $FILES ':(exclude)*.config' > "$patchesDir/p1.diff"
	revertChanges
	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"${text}_2 %d\", _deku_var_test++);"
	git -C "$srcDir" diff -- $FILES ':(exclude)*.config' > "$patchesDir/p2.diff"
	revertChanges
	appendBeforeFunction "$srcDir/net/ethernet/eth.c" eth_type_trans "int _deku_var_test = 0;"
	appendToFunction "$srcDir/net/ethernet/eth.c" eth_type_trans "printk(KERN_INFO \"%s_2 %d\", __func__, _deku_var_test++);"
	git -C "$srcDir" diff -- $FILES ':(exclude)*.config' > "$patchesDir/p3.diff"
	revertChanges
	appendBeforeFunction "$srcDir/include/net/arp.h" __ipv4_confirm_neigh "extern int _deku_var_test;"
	git -C "$srcDir" diff -- $FILES ':(exclude)*.config' > "$patchesDir/p4.diff"
	revertChanges
	dekuDeploy -p "$localPatchesDir/p1.diff" \
			   -p "$localPatchesDir/p2.diff" \
			   -p "$localPatchesDir/p3.diff" \
			   -p "$localPatchesDir/p4.diff" || exitError 17
	clearLogs
	remoteSh "ip -s -s neigh flush all; $downloadCmd"
	checkIfDmesgContains "${text}_2" || exitError 18
	checkIfDmesgContains "eth_type_trans_2" || exitError 19
	checkIfDmesgNOTContains "${text}_1" || exitError 20
	checkIfDmesgNOTContains "eth_type_trans_1" || exitError 21

	logStep "Test multi patches with wildcard"
	sed -i "s/%s_2/%s_3/g" $patchesDir/p*.diff
	sed -i "s/DEKU patch tcp_syn_options test_2/DEKU patch tcp_syn_options test_3/g" $patchesDir/p*.diff
	dekuDeploy -p $localPatchesDir/*.diff || exitError 22
	clearLogs
	remoteSh "ip -s -s neigh flush all; $downloadCmd"
	checkIfDmesgContains "${text}_3" || exitError 23
	checkIfDmesgContains "eth_type_trans_3" || exitError 24
	checkIfDmesgNOTContains "${text}_2" || exitError 25
	checkIfDmesgNOTContains "eth_type_trans_2" || exitError 26
	fi

	logStep "Test broken patch"
	sed -i "s/eth_type_trans/ethX_type_trans/g" $patchesDir/*.diff
	out=$(dekuDeploy --stdout -p $localPatchesDir/*.diff) && exitError 27
	grep -q "Failed to apply patch" <<< "$out" || exitError 28

	logStep "OK"

	return 0
}

main()
{
	test
}

main $@
