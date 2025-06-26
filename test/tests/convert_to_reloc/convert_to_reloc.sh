#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test address conversion for relocation in jmp/call instructions

FILES=""
DESCRIPTION="Convert to relocations"
. test/common.sh

# prepareKernel // leave this commit to avoid rebuilding the kernel for this test
test()
{
	local file=$1
	local fun=$2

	local dir=test/tests/convert_to_reloc
	local outDisFile=/tmp/disass.txt

	if [[ $KERNEL_VER == v6.8 ]]; then
		[[ $fun == "fib_multipath_hash" ]] && return
		[[ $fun == "napi_complete_done" ]] && return
		[[ $fun == "__ip_rt_update_pmtu" ]] && return
	fi
	logStep -n "$file $fun... "
	./elfutils --disassemble -f "$dir/$file/$file.o" -s $fun -r > $outDisFile
	sed -i 's/ *$//' $outDisFile
	sed -ri 's/shr    \$1,(.+)/shr    \1/' $outDisFile
	sed -ri 's/sar    \$1,(.+)/sar    \1/' $outDisFile
	# cp $outDisFile $dir/$file/$fun.dis
	cmp $outDisFile $dir/$file/$fun.dis || { \
		echo "" >> $LOG_FILE \
		echo "\n"./elfutils --disassemble -f "$dir/$file/$file.o" -s $fun -r >> $LOG_FILE \
		echo "=======" >> $LOG_FILE; \
		cat $outDisFile >> $LOG_FILE; \
		echo "=======" >> $LOG_FILE; \
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
		for func in $dir/$file/*.dis; do
			func=`basename ${func%.*}`
			test $file $func
		done
	done
}

main $@
