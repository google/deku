#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test livepatch relocations

FILES="arch/x86/kernel/hpet.c drivers/gpu/drm/i915/gem/i915_gem_mman.c"
DESCRIPTION="Relocation"
KERNEL=$KERNEL_VERSION_5_15
. test/common.sh

checkRelocations()
{
	local kernVer=$1
	local srcfile=$2
	local fun=$3
	local text=$4
	local srcDir=$(sourceDir $KERNEL_VER)

	local tmpreloc=/tmp/reloc
	local origin="test/tests/relocation/$kernVer/$(filenameNoExt $srcfile)"

	revertChanges

	appendToFunction "$srcDir/$srcfile" $fun "$text"

	dekuBuild || exit 1

	local koFile=$(find $WORKDIR -name "deku_*.ko")
	readelf -s -W "$koFile" | sed -n 's/.\+\ \[0xff20\] \(\.klp.*\)/\1/p' | sort > "$tmpreloc"

	logStep -n "Checking relocations for $srcfile... "
	# cp $tmpreloc $origin
	cmp $tmpreloc $origin || { logErr "Fail"; exit 2; }
	logStep "OK"
}

test()
{
	prepareKernel $KERNEL_VERSION_5_15

	checkRelocations "5_15" "arch/x86/kernel/hpet.c" "hpet_rtc_interrupt" "pr_info(\"test\");"
	checkRelocations "5_15" "drivers/gpu/drm/i915/gem/i915_gem_mman.c" "i915_gem_mmap" "pr_info(\"test\");"
	# checkRelocations "5_15" "net/ipv4/netfilter/nf_log_ipv4.c" "nf_log_ip_packet" "pr_info(\"test\");"
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
