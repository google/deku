#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku

# Functions return "0" as success

# export TEST_ON_CHROMEBOOK=1

export CHROMEOS=
export VM_TEST=
# export LOCAL_TEST=1
EXIT_ON_FAILURE=

export KERNEL_VERSION="KERNEL_VERSION_NOT_SET"

source test/common.sh

# ❯ rg "Building the kernel..." *
tests_that_build_kernel=(
	"atomic_replace"
	"dependend_module"
	"dependent_changes"
	"detect_object_file"
	"global_variables"
	"no_valid_changes"
	"patch"
	"static_keys"
	"static_local_variables"
	"stalled_task"
	"string_changed"
	"symbol_index"
	"weak_function"
)

checkErr()
{
	local kernelVersion=$1
	local err=$2
	local test=$3
	local testdesc=$4

	rm -rf test/logs/fails/$(basename $(logFile))
	rm -rf test/logs/fails/$(basename $(logFile build))
	rm -rf test/logs/fails/$(basename $(logFile cros))
	rm -rf test/logs/fails/$(basename $(logFile qemu))
	rm -rf test/logs/fails/$(basename $(logFile vm))
	rm -rf test/logs/pass/$(basename $(logFile))
	rm -rf test/logs/pass/$(basename $(logFile build))
	rm -rf test/logs/pass/$(basename $(logFile cros))
	rm -rf test/logs/pass/$(basename $(logFile qemu))
	rm -rf test/logs/pass/$(basename $(logFile vm))
	rm -rf test/logs/fails/workdir/$TEST_ID
	rm -rf test/logs/pass/workdir/$TEST_ID

	if [[ $err != 0 ]]; then
		logErr "${RED}$testdesc [$test] test failed with error code: $err${NC}"
		echo "$TEST_ID: $err" >> test/logs/failed_test
		echo "Failed with error code: $err" >> $(logFile)
		[[ $EXIT_ON_FAILURE ]] && exit 1
		mkdir -p test/logs/fails/workdir
		mv -f $(logFile) test/logs/fails/
		mv -f $(logFile build) test/logs/fails/ 2>/dev/null
		mv -f $(logFile cros) test/logs/fails/ 2>/dev/null
		mv -f $(logFile qemu) test/logs/fails/ 2>/dev/null
		mv -f $(logFile vm) test/logs/fails/ 2>/dev/null
		mv -f "$WORKDIR" test/logs/fails/workdir/$TEST_ID
		[[ $CHROMEOS || $VM_TEST ]] || mv $(logFile qemu) test/logs/fails/ 2>/dev/null
	else
		echo $TEST_ID >> test/logs/pass_test
		mkdir -p test/logs/pass/workdir
		mv $(logFile) test/logs/pass/
		mv -f $(logFile build) test/logs/pass/ 2>/dev/null
		mv -f "$WORKDIR" test/logs/pass/workdir/$TEST_ID
		[ -e test/logs/fails/workdir ] && [ -z "$( ls -A 'test/logs/fails/workdir' )" ] && rm -rf test/logs/fails/workdir
		[ -e test/logs/fails ] && [ -z "$( ls -A 'test/logs/fails' )" ] && rm -rf test/logs/fails
	fi
	rm -f $(logFile build) test/logs/fails/ 2>/dev/null
	rm -f $(logFile cros) test/logs/fails/ 2>/dev/null
	rm -f $(logFile qemu) test/logs/fails/ 2>/dev/null
	rm -f $(logFile vm) test/logs/fails/ 2>/dev/null

}

function revert()
{
	local kernelVersion=$1
	local test=$2
	local files=$(bash test/tests/$test/$test.sh --files)
	[[ $files == "" ]] && return
	local validFiles=()
	for file in $files; do
		# [[ $VM_TEST != "" ]] && [[ -s "$SOURCE_DIR/$file" ]] touch -m -t 200001010101 "$SOURCE_DIR/$file"
		[[ -s "$SOURCE_DIR/$file" ]] && validFiles+=($SOURCE_DIR/$file)
	done

	git -C "$SOURCE_DIR" restore $(git -C "$SOURCE_DIR" ls-files $files 2>/dev/null | xargs) || git -C "$SOURCE_DIR" restore .
	if [[ $VM_TEST == "" ]]; then
		echo "$(git -C $SOURCE_DIR status -s -- ':!debian')" >> $LOG_FILE
	else
		remoteSh 'git -C linux status -s -- ':!debian''
	fi

	if isKernelBuildClean && isCurrentKernelDeployed; then
		touch -m -t 200001010101 ${validFiles[*]}
		touch "$SOURCE_DIR/vmlinux"
		touch "$SOURCE_DIR/Makefile"
	fi
}

testId()
{
	local kernelVersion=$1
	local test=$2
	echo $test-$TEST_PLATFORM-${kernelVersion//\//_}
}

function runTest()
{
	local kernelVersion=$1
	local test=$2
	local res=0

	# Restore all files that are used in tests
	local files=()
	for file in $(bash test/tests/$test/$test.sh --files); do
		[[ ! " ${files[*]} " =~ " ${file} " ]] && files+=($file)
	done
	git -C "$SOURCE_DIR" restore $(git -C "$SOURCE_DIR" ls-files "${files[@]}" 2>/dev/null | xargs)

	local rebuildKernel=1

	CURRENT_CROS_KERNEL_VERSION=$(crosKernelVersion $kernelVersion)

	local testScript=test/tests/$test/$test.sh
	local desc=$(bash $testScript --description)

	if grep -q "\b$TEST_ID\b" test/logs/pass_test > /dev/null 2>&1; then
		logInfo "Skip '$desc' on kernel $kernelVersion"
		return
	fi

	logStep "============== Run $desc [$test] on kernel: $kernelVersion =============="
	revert $kernelVersion $test
	rm -rf "$WORKDIR"
	rm -f $(logFile)
	rm -f $(logFile build)
	rm -f $(logFile cros)
	rm -f $(logFile qemu)
	rm -f $(logFile vm)

	skipPrepareKernel=
	skipPrepareKernelAndDeploy=
	if grep -q "\bprepareKernelAndDeploy\b" $testScript; then
		skipPrepareKernel=1
		skipPrepareKernelAndDeploy=1
	fi
	if grep -q "\bbuildKernelToLaunch\b" $testScript; then
		skipPrepareKernelAndDeploy=1
	fi

	if [[ "$skipPrepareKernel" != 1 ]] && [[ "$skipPrepareKernelAndDeploy" == 1 ]]; then
		logStep "Prepare kernel $kernelVersion"
		prepareKernel $kernelVersion
		res=$?
		[[ $res != 0 ]] && return $res
	fi

	if [[ "$skipPrepareKernelAndDeploy" != 1 ]]; then
		if [[ "$rebuildKernel" == 1 ]]; then
			if grep -q "\bdekuDeploy\b" $testScript; then
				logStep "Prepare, build and deploy kernel $kernelVersion"
				prepareKernelAndDeploy $kernelVersion
				res=$?
				[[ $res != 0 ]] && return $res
			else
				logStep "Prepare and build kernel $kernelVersion"
				prepareKernelAndBuild $kernelVersion
				res=$?
				[[ $res != 0 ]] && return $res
			fi
			rebuildKernel=
		fi
		if grep -q "\bdekuDeploy\b" $testScript; then
			runQemu $kernelVersion
			res=$?
			[[ $res != 0 ]] && return $res
		fi
	fi

	cp -f $(kernelConfigFile) /tmp/deku_test_config.backup

	# Save exported variables to a temp file
	export -p > /tmp/deku_test_env.sh

	# Run the test script in a clean environment, sourcing the variables
	bash -c "source /tmp/deku_test_env.sh; bash $testScript --kernel $kernelVersion"
	res=$?
	diff --ignore-matching-lines='^#' $(kernelConfigFile) /tmp/deku_test_config.backup >/dev/null && logInfo "Kernel config file is the same"
	diff --ignore-matching-lines='^#' $(kernelConfigFile) /tmp/deku_test_config.backup >/dev/null || { \
		logInfo "Kernel config file changed"; \
		diff --ignore-matching-lines='^#' -y $(kernelConfigFile) /tmp/deku_test_config.backup | grep -e ">" -e "<" -e "|"; \
		cp -f /tmp/deku_test_config.backup $(kernelConfigFile); \
		markKernelAsDirty; \
	}
	[[ $EXIT_ON_FAILURE == "" ]] && revert $kernelVersion $test
	checkErr $kernelVersion $res $test "$desc"

	return $res
}

main()
{
	local run_base_tests=
	local run_lts_tests=
	local kernVer=
	local rerun=
	local test=

	# In the first run init vars for logging
	for ((i=1; i<=$#; i++))
	do
		case ${!i} in
			--chromebook)
			export CHROMEOS=1
			export TEST_PLATFORM=cros
			;;
			--vm)
			export VM_TEST=1
			export TEST_PLATFORM=vm
			;;
			--android)
			export ANDROID=1
			export TEST_PLATFORM=android
			;;
			--lts)
			export TEST_PLATFORM=baseLTS
			run_lts_tests=1
			;;
			--test)
			local j=$((i+1))
			test=${!j}
			;;
			--kernel)
			local j=$((i+1))
			kernVer=${!j}
			;;
		esac
	done

	if [[ $run_lts_tests ]]; then
		if [[ $kernVer == "origin/master" ]]; then
			kernVer=$(git -C "$KERNELS_DIR/linux-stable" tag -l --sort=v:refname | tail -n 1)
		else
			kernVer=$(git -C "$KERNELS_DIR/linux-stable" tag -l --sort=v:refname | grep -F ${kernVer}. | tail -n 1)
		fi
	fi
	export TEST_ID=$(testId $kernVer $test)
	export LOG_FILE=$(logFile)

	# logging has been inited

	mkdir -p test/logs/pass
	[[ $EXIT_ON_FAILURE ]] && logWarn "Exit on failure"

	while [[ $# -gt 0 ]]; do
		case $1 in
			--chromebook)
			logInfo "Run test on Chromebook"
			shift
			;;
			--lts)
			logInfo "Run tests on LTS and recent kernel versions"
			shift
			;;
			--vm)
			logInfo "Run test on VM"
			shift
			;;
			--android)
			export DEPLOY_PARAMS=localhost:5582
			logInfo "Run test on Android"
			shift
			;;
			--test)
			logInfo "Run $test test"
			shift
			shift
			;;
			--system)
			logInfo "Run on $2"
			shift
			shift
			;;
			--kernel)
			logInfo "Run on $kernVer"
			shift
			shift
			;;
			--index)
			index=$2
			logInfo "Test index: $index"
			export SSH_PORT_OFFSET=$index
			shift
			shift
			;;
			--rerun)
			rerun=1
			shift
			;;
			--port)
			export SSH_PORT_OVERRIDE=$2
			logInfo "SSH port: $SSH_PORT_OVERRIDE"
			shift
			shift
			;;
			--testid)
			testId $kernVer $test
			exit 0
			;;
			--ssh)
			ssh root@localhost -p $SSH_PORT $SSHPARAMS
			exit 0
			;;
			-*|--*|*)
			logErr "Unknown option $1"
			exit 1
			;;
		esac
	done

	export CURRENT_TEST=$test
	export KERNEL_VERSION=$kernVer
	exportVars $kernVer

	if [[ $VM_TEST ]]; then
		mkdir -p /tmp/deku-vm-mount
		if mount | grep -qF "/tmp/deku-vm-mount"; then
			# if /tmp/deku-vm-mount is empty then umount /tmp/deku-vm-mount
			if [[ -z "$(ls -A /tmp/deku-vm-mount)" ]]; then
				umount /tmp/deku-vm-mount
				runQemu
			fi
			# use currently running instance
		else
			runQemu
		fi
	fi

	if [[ ! $CHROMEOS$VM_TEST$ANDROID ]]; then
		if [[ ! -f "$ROOTFS_IMG" ]]; then
			logInfo "Rootfs image is not found. Generating..."
			pushd test
			sudo modprobe nbd
			sudo ./mkrootfs.sh
			popd
		fi

		if [[ "$SOURCE_DIR" == "" || ! -d "$SOURCE_DIR" ]]; then
			logInfo "Can't find kernel sources dir $SOURCE_DIR. Downloading..."
			prepareKernelSources $kernVer
		else
			git -C "$KERNELS_DIR/linux-stable" fetch
		fi
	fi

	if [[ $rerun ]]; then
		local testId=$(testId $kernVer $test)
		sed -i "/$testId/d" test/logs/pass_test 2>/dev/null
		sed -i "/$testId/d" test/logs/failed_test 2>/dev/null
	fi

	runTest $kernVer $test
}

main $@
