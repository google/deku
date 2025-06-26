#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test that check if out-of-tree module is handled correctly.

FILES=""
DESCRIPTION="Out-of-tree module"
. test/common.sh

checkOotModule()
{
	local buildDir=$(buildDir $KERNEL_VER)
	local originModDir=test/tests/oot_module
	local modDir=/tmp/deku_test_oot_module
	local dekuModDir=$modDir
	local LLVM=
	local SUDO=
	local linuxHeaders=

	rm -rf $modDir
	cp -rf $originModDir $modDir

	if [[ $CHROMEOS ]]; then
		LLVM="LLVM=1"
		linuxHeaders="-k $buildDir"
	elif [[ $VM_TEST ]]; then
		modDir=/tmp/deku-vm-mount/deku_test_oot_module
		dekuModDir=../deku_test_oot_module
		SUDO=sudo
	else
		buildDir="/kernel/${BUILD_DIR##*/}"
		linuxHeaders="-k $buildDir"
	fi

	logStep "Build and load module..."
	if [[ $VM_TEST ]]; then
		rm -rf $modDir
		copyToRemote "$originModDir" deku/$dekuModDir
		sed -i '/^\smake -C /d' $modDir/Makefile || exitError
		sed -i 's/^#\smake -C /\tmake -C /g' $modDir/Makefile || exitError
		runCmd "bash -c 'cd /home/test/deku/$dekuModDir && make'" || exitError
		remoteSh "sudo insmod deku/$dekuModDir/test_module.ko" || exitError
	elif [[ $CHROMEOS ]]; then
		make -C $modDir KERNEL_DIR=$buildDir LLVM=1 || exitError
		copyToRemote "$modDir/test_module.ko"
		remoteSh "insmod test_module.ko"
	else
		runCmd "make -C $modDir KERNEL_DIR=$buildDir" || exitError
		copyToRemote "$modDir/test_module.ko" "/tmp/"
		remoteSh "insmod /tmp/test_module.ko"
	fi

	local text=$(remoteShOut "cat /proc/deku_test")
	# [[ "$text" == "DEKU test procfs. Param value: 0" ]] || exitError

	logStep "Modify and apply changes to module..."
	sed -i "s/DEKU test procfs/DEKU xtest procfs/g" $modDir/module_helper.c
	dekuDeploy -v -b $dekuModDir $linuxHeaders || exitError 1

	text=$(remoteShOut "cat /proc/deku_test")
	[[ "$text" == "DEKU xtest procfs. Param value: 0" ]] || exitError

	logStep "Check if reverting changes is handled correctly..."
	cp -f $originModDir/module_helper.c $modDir/module_helper.c

	out=$(dekuDeploy --log --builddir $dekuModDir $linuxHeaders) || exitError 2
	grep -q "Reverting changes from module_helper.c" <<< "$out" || exitError

	logStep "Check if patch for module works correctly..."
	dekuDeploy --builddir $dekuModDir -p "$dekuModDir/test.patch" $linuxHeaders || exitError 3
	text=$(remoteShOut "cat /proc/deku_test")
	[[ "$text" == "DEKU test procfs. Param value: 3" ]] || exitError

	logStep "Verify that the presence of the module is detected..."
	remoteSh "$SUDO rmmod test_module.ko"
	cp -f $originModDir/module_helper.c $modDir/module_helper.c
	sed -i "s/DEKU test procfs/DEKU xtestx procfs/g" $modDir/module_helper.c
	out=$(dekuDeploy --log --builddir $dekuModDir $linuxHeaders) && exitError 4
	grep -q "Can't apply changes for module_helper.c because the 'test_module' module is not loaded" <<< "$out" || exitError

	logStep "Check if forbidden changes in module are detected..."
	appendToFunction $modDir/module_helper.c "helper_print_init_message" "printk(KERN_INFO);"
	out=$(dekuBuild --log --builddir $dekuModDir $linuxHeaders) && exitError 5
	[[ $? != $ERROR_FORBIDDEN_MODIFY ]] && exitError
	if [[ $CHROMEOS$VM_TEST ]]; then
		grep -q "The 'helper_print_init_message' function is not allowed to modify." <<< "$out" || exitError
	else
		grep -q "The 'helper_print_init_message' function is forbidden to modify. The function is non-local" <<< "$out" || exitError
	fi

	if [[ $VM_TEST == "" && $KERNEL_VER != v6.15* ]]; then
		logStep "Check if no-valid kernel headers are detected..."
		out=$(dekuDeploy --log --builddir $dekuModDir) && exitError 6
		[[ $? != $ERROR_INVALID_HEADERS_DIR ]] && exitError
		grep -q "Failed to find kernel headers directory. Please specify it using -k or --headersdir parameter. This is the same parameter as the -C parameter for the \`make\` command in the Makefile." <<< "$out" || exitError
	fi

	logStep "Check if invalid module dir is detected..."
	rm -f $modDir/test_module.ko
	out=$(dekuDeploy --log -v --builddir $dekuModDir $linuxHeaders) && exitError 7
	[[ $? != $ERROR_INVALID_MOD_DIR ]] && exitError
	if [[ $VM_TEST ]]; then
		grep -q "Given module directory does not contain built kernel module: /home/test/deku_test_oot_module/" <<< "$out" || exitError
	else
		grep -q "Given module directory does not contain built kernel module: $modDir/" <<< "$out" || exitError
	fi

	rm -f $modDir/Makefile
	out=$(dekuDeploy --log --builddir $dekuModDir $linuxHeaders) && exitError 8
	[[ $? != $ERROR_INVALID_BUILDDIR ]] && exitError
	if [[ $VM_TEST ]]; then
		grep -q "Given build directory is not a valid kernel or module build directory: /home/test/deku_test_oot_module/" <<< "$out" || exitError
	else
		grep -q "Given build directory is not a valid kernel or module build directory: $modDir/" <<< "$out" || exitError
	fi

	rm -rf $modDir
	out=$(dekuDeploy --log --builddir $dekuModDir $linuxHeaders) && exitError 9
	[[ $? != $ERROR_INVALID_BUILDDIR ]] && exitError
	if [[ $VM_TEST ]]; then
		grep -q "Given build directory does not exist: /home/test/deku_test_oot_module/" <<< "$out" || exitError
	elif [[ $CHROMEOS ]]; then
		grep -q "Given build directory is not a valid kernel or module build directory: $modDir/" <<< "$out" || exitError
	else
		grep -q "Given build directory does not exist: $modDir/" <<< "$out" || exitError
	fi

	return 0
}

test()
{
	checkOotModule
}

main()
{
	test
}

main $@
