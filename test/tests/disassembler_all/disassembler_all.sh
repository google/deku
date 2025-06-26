#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test generated disassembler code

FILES=""
DESCRIPTION="Disassembler all files in the kernel"
. test/common.sh

# TODO:
# prepareKernelAndDeploy // leave this commit to avoid rebuilding the kernel for this test
dissasembly()
{
	local file=$1
	local kernelFile=${file#*$BUILD_DIR/}
	local base=/tmp/deku-$TEST_ID
	local patternDir=$base-pattern

	[[ $kernelFile == vmlinux.o ]] && return

	local outFile="$patternDir/$kernelFile"
	outFile=${outFile/.o/.txt}

	[[ -e $outFile ]] && outFile=${outFile/-pattern/-current}


	mkdir -p "$(dirname $outFile)" && rm -f "$outFile"

	for fun in $(readelf -sW $file |  awk '$3 > 0 && $4 == "FUNC" {print $8}'); do
		./elfutils --disassemble -f $file -s $fun -r | sed --expression "s/^/$fun: /" >> "$outFile"
	done

	local patternFile=${outFile/-current/-pattern}
	[[ "$patternFile" == "$outFile" ]] && return
	if ! diff -q -- "$patternFile" "$outFile"; then
		local diffFile=${patternFile/-pattern/-diff}
		mkdir -p "$(dirname $diffFile)"
		diff -y --suppress-common-lines "$patternFile" "$outFile" > $diffFile
	fi
}

main()
{
	MAIN_PATH=`dirname "$0"`

	find $BUILD_DIR -name "*.o" -print0 | while read -d $'\0' file
	do
		dissasembly $file $func
	done
	exit 255
}

main $@
