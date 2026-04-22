#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if valid index for modified symbol is chosen

# DEPRECATED

FILES="net/bluetooth/mgmt.c"
DESCRIPTION="Symbol index ext"
. test/common.sh

symbolIndexTest()
{
	local file=$1
	local function=$2
	local expectedindex=$3
	local kernelversion=$4
	local modname="$(generateModuleName $file)"
	local moduledir="$WORKDIR/$modname"
	local srcDir=$SOURCE_DIR

	appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"\");"

	dekuBuild || exit 1

	local index=`grep -A 2 ".old_name = \"$function\"" "$moduledir/livepatch.c" | \
				 sed -n "s/.*old_sympos\ =\ \(.*\)/\1/p"`
	if [[ $index != $expectedindex ]]; then
		logErr "Invalid symbol index for '$function' in '$file'. Expected index '$expectedindex' got '$index'"
		exit 1
	fi
	logStep "Symbol index for $file matches... OK"
}

main()
{
	MAIN_PATH=`dirname "$0"`

	symbolIndexTest "net/bluetooth/mgmt.c" "stop_discovery" 1 $KERNEL_VERSION
	# functionCallTest "fs/proc/proc_tty.c" "t_start" "wget -q --spider google.com; timeout 1 top" $KERNEL_VERSION
	# cut -d' ' -f 3 ~/chromeos/chroot/home/mmaslanka/.cache/deku/build-linux-deku/System.map | sort | uniq -cd | sort -h
}

main $@


# symbol=t_start
# srcfilename="trace_events.c"
# objpath=vmlinux
# readelf --symbols -W "$BUILD_DIR/$objpath" | grep -E -e " FILE .+ $srcfilename$" -e " $symbol$"
# symbols=`readelf --symbols -W "$BUILD_DIR/$objpath" | grep -E -e " FILE .+ $srcfilename$" -e " $symbol$"`
# count=`grep -E " $symbol$" <<< "$symbols" | wc -l`
# [[ $count == "1" ]] && return
# logInfo "Found $count symbols with the name '$symbol'"
# index=`grep -n $srcfilename <<< "$symbols" | \
# 	   cut -f1 -d:`
# echo $index