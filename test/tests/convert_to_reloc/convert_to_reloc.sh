#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test address conversion for relocation in jmp/call instructions

FILES=""
DESCRIPTION="Convert to relocations"
. test/common.sh

# prepareKernelAndBuild // leave this commit to avoid rebuilding the kernel for this test
test()
{
	local file=$1
	local fun=$2

	local dir=test/tests/convert_to_reloc
	local outDisFile=/tmp/disass-$KERNEL_VER.txt

	if [[ $KERNEL_VER == v6.8 ]]; then
		[[ $fun == "fib_multipath_hash" ]] && return
		[[ $fun == "napi_complete_done" ]] && return
		[[ $fun == "__ip_rt_update_pmtu" ]] && return
	fi

	if [[ $VM_TEST != "" ]]; then
		mkdir -p $WORKDIR/../$file
		cp $dir/$file/$file.o $WORKDIR/../$file/$file.o
		cp $dir/$file/$fun.dis $WORKDIR/../$file/$fun.dis
		originDir=$dir
		dir=.
		outDisFile=$(basename $outDisFile)
	fi

	logStep -n "$file $fun... "
	runCmd "./elfutils --disassemble -f $dir/$file/$file.o -s $fun -r > $outDisFile"
	if [[ $VM_TEST != "" ]]; then
		outDisFile=$WORKDIR/../$outDisFile
		dir=$originDir
	fi
	sed -i 's/ *$//' $outDisFile
	sed -ri 's/shr    \$1,(.+)/shr    \1/' $outDisFile
	sed -ri 's/sar    \$1,(.+)/sar    \1/' $outDisFile
	sed -i 's/\r/\n/g; s/\n$//' $outDisFile
	# cp $outDisFile $dir/$file/$fun.dis
	cmp $outDisFile $dir/$file/$fun.dis || { \
		echo >> $LOG_FILE; \
		diff -y $outDisFile $dir/$file/$fun.dis >> $LOG_FILE; \
		logErr "Failed"; \
		exit 1; \
	}
	logStep "OK"
}

main()
{
	MAIN_PATH=`dirname "$0"`

	local filec=timerfd
	local dir=test/tests/convert_to_reloc
	for file in $dir/*/; do
		file=`basename $file`
		[[ $file == "mmap2" ]] && continue # TODO
		for func in $dir/$file/*.dis; do
			func=`basename ${func%.*}`
			test $file $func
		done
	done
}

main $@
