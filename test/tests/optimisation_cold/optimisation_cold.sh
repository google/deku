#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if compiler optimizations that produce split functions with the .cold
# sufix are properly detected.
#
# Add new case:
# 1. Find the function in origin object file is .cold
# 2. Choose one local function that is called from #1
# 3. Add a new case. The second parameter to 'coldFunctionTest' is function from #1, third parameter is function from #2

FILES="net/core/dev.c net/core/sock.c"
DESCRIPTION="Optimisation - Cold"
. test/common.sh

TAGS=test/tags/tags

function findColdFunction()
{
	local srcDir=$(sourceDir $KERNEL_VER)
	local files=`find "$BUILD_DIR/drivers" -name "*.o" ! -name '*.mod.o'  -not -path "*lib*"`
	while read -r file;
	do
		local funcs=`readelf -sW "$file" | grep -F FUNC | grep -F ".cold" | grep -o '[^ ]*$'`
		[[ "$funcs" != "" ]] && echo "$file" && continue
		local cfile=${file/.o/.c}
		cfile=${cfile#*$BUILD_DIR/}
		cfuncs=`$TAGS "$srcDir/$cfile" | sed -nr "s/.*\ (\w+):(.+)$/\1/p" 2>/dev/null`
		[[ $? != 0 ]] && continue
		while read -r fun;
		do
			[[ $fun == "" ]] && continue
			while read -r cfun;
			do
				[[ $cfun == "" ]] && continue
					local reference=$(./elfutils --referenceFrom -f "$file" -s $cfun 2>/dev/null)
					if [[ "$reference" ]]; then
						grep -q f:$cfun <<< "$reference" || continue

echo -n "$fun "
echo "$reference"

						reference=$(echo "$reference" | head -n 1)
						reference=${reference#"f:"}
						reference=${reference#"v:"}
						fun=${fun%".cold"}
						[[ "$fun" == "$reference" ]] && continue
						logStep "Use following line:"
						echo "coldFunctionTest $cfile $cfun $reference"
						return

					fi
			done <<< "$cfuncs"
		done <<< "$funcs"
	done <<< "$files"
}

coldFunctionTest()
{
	local file=$1
	local function=$2
	local coldFunction=$3
	local filename=$(filenameNoExt "$file")
	local srcDir=$(sourceDir $KERNEL_VER)

	revertChanges 2>/dev/null

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"\");"

	logStep -n "Detection cold function ($file)... "

	out=$(dekuBuild --log -v) || { logErr "Fail"; exitError 1; }
	local objFile=$(find $WORKDIR -name "$filename.o")
	readelf -sW "$objFile" >> $LOG_FILE
	readelf -sW "$objFile" | grep -q "$coldFunction.cold" || { logErr "Fail"; exitError 2; }
	grep -q "The '$coldFunction.cold' function is forbidden to modify. This function is called from:" <<< "$out" || { logErr "Fail"; exitError 3; }
	grep -q "^f:$coldFunction\b" <<< "$out" || { logErr "Fail"; exitError 4; }

	logStep "OK"
}

test()
{
	# findColdFunction
	# exit 1
	if [[ $KERNEL_VER == v6.8 ]]; then
		coldFunctionTest "drivers/gpu/drm/display/drm_dp_mst_topology.c" "drm_dp_mst_dump_sideband_msg_tx" "drm_dp_mst_dump_sideband_msg_tx"
	else
		coldFunctionTest "net/core/dev.c" "qdisc_pkt_len_init" "__dev_queue_xmit"
		coldFunctionTest "net/core/sock.c" "req_prot_init" "proto_register"
	fi
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
