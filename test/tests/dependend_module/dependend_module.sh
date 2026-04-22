#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if module from which function has been modified is loaded into the kernel
# if it's not loaded then detect it and return error.

FILES="drivers/input/misc/uinput.c drivers/hid/hid-logitech-hidpp.c"
DESCRIPTION="Dependend module"
. test/common.sh

checkAndResolveDep()
{
	local file=$1
	local func=$2
	local modName=$3

	local koPath="${file/".c"/".ko"}"
	local text="pr_info(\"test\");"
	local srcDir="$SOURCE_DIR"

	logStep "Detect that $(basename $koPath) module is not loaded"
	appendToFunction "$srcDir/$file" $func "$text"

	[[ $CHROMEOS ]] && remoteSh "rmmod -f $(basename $koPath)"
	out=$(dekuDeploy --stdout -v)
	local res=$?
	[[ $res != $ERROR_DEPEND_MODULE_NOT_LOADED ]] && { logErr "Invalid exit code: $res"; exitError; }

	grep -q "Can't apply changes for $file because the '$modName' module is not loaded" <<< "$out" || { logErr "Fail"; exitError; }

	logStep "Upload and load module $(basename $koPath)"

	if [[ $VM_TEST ]]; then
		remoteSh "cd linux; sudo insmod $koPath"
	elif [[ $CHROMEOS ]]; then
		remoteSh "modprobe $(filenameNoExt $koPath)"
	else
		copyToRemote "$BUILD_DIR/$koPath" "/tmp/"
		remoteSh "insmod /tmp/$(basename $koPath)"
	fi

	dekuDeploy || { remoteSh "lsmod"; exitError; }
	logStep "Depended module for $file resolved successfuly"
}

test()
{
	prepareKernelAndDeploy $KERNEL_VER +CONFIG_INPUT_UINPUT +CONFIG_LEDS_CLASS_MULTICOLOR +CONFIG_HID_LOGITECH +CONFIG_HID_LOGITECH_HIDPP
	runQemu

	# checkAndResolveDep drivers/input/misc/uinput.c uinput_request_send uinput
	checkAndResolveDep drivers/input/misc/uinput.c uinput_create_device uinput
	checkAndResolveDep drivers/hid/hid-logitech-hidpp.c hidpp_ff_upload_effect hid_logitech_hidpp

	logStep "OK"

	return 0
}

main()
{
	# TODO: Remove once ROX allocations for livepatch will be fixed
	[[ $KERNEL_VER == "origin/master" ]] && return;
	[[ $ANDROID ]] && return
	if [[ $LOCAL_TEST != "" ]]; then
		:
	else
		test
	fi
}

main $@
