#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if disassembly is properly generated from object file

FILES=""
DESCRIPTION="Dissasembly"
. test/common.sh

# prepareKernelAndBuild // leave this commit to avoid rebuilding the kernel for this test
test()
{
	local file=$1
	local fun=$2
	local outFile=/tmp/disass-$KERNEL_VER.txt

	local dir=test/tests/dissasembly/files

	runCmd "./elfutils --disassemble -f $dir/$file.o -s $fun"
	runCmd "./elfutils --disassemble -f $dir/$file.o -s $fun" > $outFile
	sed -i 's/ *$//' $outFile
	sed -i 's/\r/\n/g; s/\n$//' $outFile
	logStep -n "$file $fun... "
	# cp $outFile $dir/$fun.dis
	cmp $outFile $dir/$fun.dis || { \
		echo >> $LOG_FILE; \
		diff -y $outFile $dir/$fun.dis >> $LOG_FILE; \
		logErr "Failed"; \
		exit 1; \
	}
	logStep "OK"
}

main()
{
	MAIN_PATH=`dirname "$0"`

	test i915_gem_mman i915_gem_mmap
	test hpet hpet_clkevt_legacy_resume.cold
	test timerfd __x64_sys_timerfd_create
	test mmap __do_sys_brk
	test mmap vm_unmapped_area
	test route fnhe_hashfun
	test dev net_rx_action
	test intel_gtt i915_vm_lock_objects
}

main $@
