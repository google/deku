#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check that the generated 'patch.o' file contains the expected symbols
# Test whether fastbuild produce the same file as using kbuild

# DEPRECATED
FILES=""
DESCRIPTION="ELF symbols"
. test/common.sh

cmdBuildFilePath()
{
	local srcfile=$1
	local file="${srcfile##*/}"
	local dir=`dirname "$srcfile"`
	echo "$BUILD_DIR/$dir/.${file/.c/.o.cmd}"
}

checkElfStruct()
{
	local kernver=$1
	local srcfile=$2
	local fun=$3
	local text=$4
    local kbuild=$5
	local srcDir=$(sourceDir $KERNEL_VERSION)

	local filename=$(filenameNoExt "$srcfile")
	local modname="$(generateModuleName $srcfile)"
	local moduledir="$WORKDIR/$modname"
	local tmprel=/tmp/rel
	local tmpsec=/tmp/sec
	local originrel="test/tests/elfsym/$kernver/$modname.rel"
	local originsec="test/tests/elfsym/$kernver/$modname.sec"

    local kbuildartifacts=("build_modules.log" "Makefile_modules" "$filename.ko" ".$filename.ko.cmd" "$filename.mod"
                           "$filename.mod.c" ".$filename.mod.cmd" "$filename.mod.o" ".$filename.mod.o.cmd" ".$filename.o.cmd"
                           "_$filename.ko" "._$filename.ko.cmd" "_$filename.mod" "_$filename.mod.c" "._$filename.mod.cmd" "_$filename.mod.o"
                           "._$filename.mod.o.cmd" "._$filename.o.cmd")

	prepareKernelAndDeploy $KERNEL_VER

	appendToFunction "$srcDir/$srcfile" $fun "$text"

    if [[ $kbuild == 1 ]]; then
        local cmdfilepath=$(cmdBuildFilePath $srcfile)
        mv "$cmdfilepath" "${cmdfilepath}_"
        dekuBuild || exit 1
        mv "${cmdfilepath}_" "$cmdfilepath"
        if [[ ! -f "$moduledir/Makefile_modules" ]]; then
			logErr "kbuild was not used bo build modules"
            exit 2
		fi
        for file in "${kbuildartifacts[@]}"; do
            [[ ! -f "$moduledir/$file" ]] && { logErr "Can't find file '$file' from kbuild"; exit 3; }
        done
        logStep "Kbuild build was used... OK"
    else
        dekuBuild || exit 4
		if [[ -f "$moduledir/Makefile_modules" ]]; then
			logErr "kbuild was used to build modules but fast build was expected"
            exit 5
		fi
		for file in "${kbuildartifacts[@]}"; do
            [[ -f "$moduledir/$file" ]] && { logErr "Found unexpected file '$file' from kbuild"; exit 6; }
        done
        logStep "Fast build was used... OK"
    fi

	objdump -r "$moduledir"/patch.o | grep R_X86_64 | sed 's/\([a-z0-9]\+\)\ \(.\+\ [a-zA-Z0-9_\.]\+\).*/\2/' > "$tmprel"
	readelf -S -W "$moduledir"/patch.o | tail -n +6 | head -n -5 | cut -c 7- | awk '{print $1}' > "$tmpsec"

	echo -n "Checking ELF structure for $srcfile... "
	cmp $tmpsec $originsec || { echo "Failed"; exit 7; }
	cmp $tmprel $originrel || { echo "Failed"; exit 8; }
	# cmp $tmpsec $originsec || { echo "Failed"; cp $tmpsec $originsec; }
	# cmp $tmprel $originrel || { echo "Failed"; cp $tmprel $originrel; }
	logStep "OK"
}

checkElfStructAndKbuild()
{
	checkElfStruct "$@" 0
	checkElfStruct "$@" 1
}

main()
{
	MAIN_PATH=`dirname "$0"`

	checkElfStructAndKbuild "5_15" "drivers/rtc/rtc-cmos.c" "rtc_handler" "pr_info(\"test\");"
	checkElfStructAndKbuild "5_15" "net/ipv4/arp.c" "arp_create" "pr_info(\"arp create test\\\n\");"
	checkElfStructAndKbuild "5_15" "fs/ext4/fsync.c" "ext4_sync_file" "pr_info(\"test\");"
	checkElfStructAndKbuild "5_15" "fs/sync.c" "sync_filesystem" "pr_info(\"test\");"
	checkElfStruct "5_15" "arch/x86/kernel/hpet.c" "hpet_rtc_interrupt" "pr_info(\"test\");" 0
}

main $@
