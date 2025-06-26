#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test livepatch relocations

# readelf -s -W vmlinux | grep -A 30  -e "\bhpet.c\b" -e "\birq_handler\b"

FILES="arch/x86/kernel/hpet.c drivers/gpu/drm/i915/gem/i915_gem_mman.c net/ipv4/netfilter/nf_log_ipv4.c"
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

	local tmpreloc=/tmp/reloc-$KERNEL_VER
	local origin="test/tests/relocation/$kernVer/$(filenameNoExt $srcfile)"

	revertChanges

	appendToFunction "$srcDir/$srcfile" $fun "$text"

	dekuBuild || exit 1

	local koFile=$(find $WORKDIR -name "deku_*.ko")
	readelf -s -W "$koFile" | sed -n 's/.\+\ \[0xff20\] \(\.klp.*\)/\1/p' | env LC_COLLATE=C sort > "$tmpreloc"
	sed -i 's/\r/\n/g; s/\n$//' $tmpreloc

	logStep -n "Checking relocations for $srcfile... "
	cp $tmpreloc $origin
	cmp $tmpreloc $origin || { echo >> $LOG_FILE; diff -y $tmpreloc $origin >> $LOG_FILE; logErr "Fail"; exit 2; }
	logStep "OK"
}

test()
{
	local dir=${KERNEL_VER%.*}
	dir=${dir/./_}
	dir=${dir:1}
	checkRelocations $dir "arch/x86/kernel/hpet.c" "hpet_rtc_interrupt" "pr_info(\"test\");"
	checkRelocations $dir "drivers/gpu/drm/i915/gem/i915_gem_mman.c" "i915_gem_mmap" "pr_info(\"test\");"
	if [[ $KERNEL_VER == v5.10.* ]]; then
		checkRelocations $dir "net/ipv4/netfilter/nf_log_ipv4.c" "nf_log_ip_packet" "pr_info(\"test\");"
	fi
}

main()
{
	if [[ $KERNEL_VER == v5.10.* || $KERNEL_VER == v5.15.* ]]; then
		test
	fi
}

main $@
