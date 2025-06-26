#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Testing making changes in different source files for the same ko object file

FILES="net/bluetooth/mgmt.c net/bluetooth/hci_event.c"
DESCRIPTION="Multi files"
. test/common.sh

checkChangesFoKoFile()
{
	local koFile=$1
	local srcDir=$(sourceDir $KERNEL_VERSION)

	shift 1
	for filefun in "$@"
	do
		local file=${filefun%,*}
		local fun=${filefun#*,}
		appendToFunction "$srcDir/$file" $fun "printk(KERN_INFO \"\");"
	done

	dekuBuild || exitError 1

	logStep -n "Generate multiple patches for one object file... "
	for filefun in "$@"
	do
		local file=${filefun%,*}
		local fun=${filefun#*,}
		local objFile="$(filenameNoExt $koFile)"
		local moduledir=$(find $WORKDIR -type d -name "deku_*")
		local klpObjectsName=$(grep "\.name =" "$moduledir/livepatch.c")
		local klpObjectsCount=$(wc -l <<< "$klpObjectsName")
		if ! grep -q "\b$objFile\b" <<< "$klpObjectsName" || [[ $klpObjectsCount != "1" ]]; then
			logErr "Livepatch is not properly prepared for $objFile. Fail"
			exitError 2
		fi
	done

	logStep "OK"
}

test()
{
	checkChangesFoKoFile "net/bluetooth/bluetooth.ko" "net/bluetooth/mgmt.c,stop_discovery" "net/bluetooth/hci_event.c,process_adv_report"
}

main()
{
	test
}

main $@
