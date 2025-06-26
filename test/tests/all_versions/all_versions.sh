#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test that check if basic functionality as add pr_info to function works on
# all supported kernel versions

FILES="net/ipv4/tcp_ipv4.c"
DESCRIPTION="All kernel versions"
KERNEL=$KERNEL_VERSION_5_15
. test/common.sh

functionCallTest()
{
	local file=$1
	local function=$2
	local cmd=$3
	local kernelversion=$4
	local text="DEKU $function test"

	prepareKernel $kernelversion
	if [[ $? != 0 ]]; then
		make -C "$SOURCE_DIR" mrproper
		rm -rf $QEMU_BUILD_DIR
		prepareKernel $kernelversion
	fi

	runQemu

	appendToFunction "$SOURCE_DIR/$file" $function "printk(KERN_INFO \"$text\\\n\");"

	clearLogs
	dekuDeploy || exit 1
	sleep 1
	remoteSh $cmd
	sleep 1
	checkIfDmesgContains "$text" || exit 2

	return 0
}

test()
{
	local buildInsideSource=$1
	# local versions=(5.4 5.5 5.6 5.7 5.8 5.9 5.10 5.11 5.12 5.13 5.14 5.15 5.16 5.17 5.18 5.19
	local versions=(5.4 5.10 5.11 5.12 5.13 5.14 5.15 5.16 5.17 5.18 5.19
					6.0 6.1 6.2 6.3 6.4 6.5 6.6 6.7 6.8 6.9 6.10 6.12 6.13 6.14 6.15 6.16 6.17 6.18 6.19 6.20
					7.0 7.1 7.2 7.3 7.4 7.5 7.7 7.7 7.8 7.9 7.10 7.12 7.13 7.14 7.15 7.17 7.17 7.18 7.19 7.20)

	git -C "$SOURCE_DIR" fetch
	[[ $buildInsideSource == 1 ]] && export BUILD_DIR=$SOURCE_DIR

	for v in "${versions[@]}"
	do
		local ver=$(git -C "$SOURCE_DIR" tag -l --sort=v:refname | grep v$v. | tail -n 1)
		[[ $ver == "" ]] && continue
		logStep "Check $ver"

		if [[ $buildInsideSource == 1 ]]; then
			prepareKernel $ver # keep prepareKernel to avoid random errors
			[[ "$v" == 6.3 || "$v" == 6.4 || "$v" == 6.5 || "$v" == 6.7 ]] && continue
		fi
		functionCallTest "net/ipv4/tcp_ipv4.c" "tcp_v4_connect" "wget -q --spider google.com" $ver
	done

	res=$?

	return $res
}

main()
{
	test 0
	# rerun test but build kernel inside source code
	test 1

	make -C "$SOURCE_DIR" mrproper
	prepareKernel $KERNEL_VERSION_5_15
	make -C "$SOURCE_DIR" mrproper

	return $?
}

main $@
