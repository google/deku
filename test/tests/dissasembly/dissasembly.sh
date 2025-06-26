#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if disassembly is properly generated from object file

FILES=""
DESCRIPTION="Dissasembly"
. test/common.sh

# prepareKernel // leave this commit to avoid rebuilding the kernel for this test
test()
{
	local file=$1
	local fun=$2

	local dir=test/tests/dissasembly/files

	./elfutils --disassemble -f "$dir/$file.o" -s $fun > /tmp/disass.txt
	sed -i 's/ *$//' /tmp/disass.txt
	logStep -n "$file $fun... "
	# cp /tmp/disass.txt $dir/$fun.dis
	cmp /tmp/disass.txt $dir/$fun.dis || { \
		cat  >> $LOG_FILE; \
		cat /tmp/disass.txt >> $LOG_FILE; \
		LogErr "Failed"; \
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
