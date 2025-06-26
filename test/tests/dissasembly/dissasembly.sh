#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if disassembly is properly generated from object file

FILES=""
DESCRIPTION="Dissasembly"
. test/common.sh

# prepareKernelAndDeploy // leave this commit to avoid rebuilding the kernel for this test
test()
{
	local file=$1
	local fun=$2
	local outFile=/tmp/disass-$KERNEL_VERSION.txt

	runCmd "./elfutils --disassemble -f test/tests/dissasembly/files/$file.o -s $fun" > $outFile
	sed -i 's/ *$//' $outFile
	sed -i 's/\r/\n/g; s/\n$//' $outFile
	logStep -n "$file $fun... "
	# cp $outFile $dir/$fun.dis
	cmp $outFile $dir/$fun.dis || { \
		echo >> $LOG_FILE; \
		diff -y $outFile $dir/$fun.dis >> $LOG_FILE; \
		logErr "Failed"; \
		return 1; \
	}
	logStep "OK"
}

main()
{
	MAIN_PATH=`dirname "$0"`
	local dir=test/tests/dissasembly/files
	if [[ $VM_TEST ]]; then
		runCmd "mkdir -p $dir" >/dev/null
		copyToRemote $dir deku/$dir/..
	fi

	test i915_gem_mman i915_gem_mmap || exitError
	test hpet hpet_clkevt_legacy_resume.cold || exitError
	test timerfd __x64_sys_timerfd_create || exitError
	test mmap __do_sys_brk || exitError
	test mmap vm_unmapped_area || exitError
	test route fnhe_hashfun || exitError
	test dev net_rx_action || exitError
	test intel_gtt i915_vm_lock_objects || exitError
	logInfo "Check expected failure..."
	test hpet hpet_setup && exitError
	logInfo "Failure... is OK" # this log is needed to not return error from above test
}

main $@
