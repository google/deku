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

. test/common.sh

declare -A Tests
bg_pids=()

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
		mv -f "$WORKDIR" test/logs/pass/workdir/$TEST_ID
		[ -e test/logs/fails/workdir ] && [ -z "$( ls -A 'test/logs/fails/workdir' )" ] && rm -rf test/logs/fails/workdir
		[ -e test/logs/fails ] && [ -z "$( ls -A 'test/logs/fails' )" ] && rm -rf test/logs/fails
	fi
	rm -f $(logFile build) test/logs/fails/ 2>/dev/null
	rm -f $(logFile cros) test/logs/fails/ 2>/dev/null
	rm -f $(logFile qemu) test/logs/fails/ 2>/dev/null
	rm -f $(logFile vm) test/logs/fails/ 2>/dev/null

}

addTest()
{
	local name=$1
	local desc=$2
	Tests["$name"]="$desc"
}

prepareLtsTests()
{
	addTest function_call "Function call"
	addTest global_variables "Global variables"
	addTest symbol_index "Symbol index"
	addTest bug "BUG()"
	addTest string_changed "String changed"
	addTest header_files_basic "Basic changes in header file"
	addTest patch
	addTest detect_object_file "Detect object file"
	addTest uncommon_symbol_name "Uncommon symbol name"
	addTest weak_function "Weak function"
	addTest dependent_changes
	addTest static_keys "Static keys"
	addTest dependend_module "Dependent module"
	addTest oot_module

	addTest builderror "Build after fixing errors"
	addTest atomic_replace "atomic_replace"
	addTest multi_files "Multi files"
	# addTest static_global_symbol "Static and Global symbol"
	# addTest notraceable "No traceable functions"


	addTest inline "Inline"
	# # addTest relocation "Relocation"
	addTest unknown_type "Relocate unknown type"
	# addTest filter_symbols "Filter symbols"
	# # Tests on QEMU
	addTest no_valid_changes "No valid changes"

	addTest static_local_variables
}

prepareTests()
{
	[[ $VM_TEST == "" ]] && addTest relocation "Relocation"
	# [[ $VM_TEST == "" ]] && addTest all_versions "All kernel versions"

	# addTest inline "Inline"
	addTest notraceable "No traceable functions"
	addTest builderror "Build after fixing errors"
	addTest static_global_symbol "Static and Global symbol"
	addTest dissasembly "Dissasembly"
	addTest convert_to_reloc "Convert to relocations"
	addTest detect_object_file "Detect object file"
	addTest multi_files "Multi files"
	addTest unknown_type "Relocate unknown type"
	addTest tracepoint_str "Copy tracepoint_str"
	addTest uncommon_symbol_name "Uncommon symbol name"
	addTest header_files_basic "Basic changes in header file"
	addTest filter_symbols "Filter symbols"
	# Tests on QEMU
	addTest symbol_index "Symbol index"
	addTest global_variables "Global variables"
	addTest no_valid_changes "No valid changes"
	addTest function_call "Function call"
	addTest bug "BUG()"
	addTest string_changed "String changed"
	addTest static_keys "Static keys"
	addTest dependent_changes
	addTest weak_function "Weak function"
	addTest atomic_replace "atomic_replace"
	addTest dependend_module "Dependent module"
	addTest patch
	addTest static_local_variables
	addTest stalled_task
	addTest oot_module

	# Other
	# addTest disassembler_all

	# Tests on Chromebook
	# addTest chromebook "Chromebook"

	# Deprecated tests
	# addTest unload "Unload"
	# addTest modules_order "Modules order"
	# addTest optimisation_cold "Optimisation - Cold"

	# Unknown tests
	# addTest elfsym "ELF symbols"
	# addTest unrelatedchanges "Unrelated changes"
	# addTest symbol_index_ext "Symbol index ext"
	# addTest multiple_func "multiple_func"
	# addTest jmp_cross_referencjump across functions" # need to finish / probably enough in disassembly test that is already checked
	# addTest calls "Callee and caller" # TODO: finish
	# addTest current_task "Current task"
}

function revert()
{
	local kernelVersion=$1
	local test=$2
	local srcDir=$(sourceDir $kernelVersion)

	local files=$(bash test/tests/$test/$test.sh --files)
	[[ $files == "" ]] && return
	local validFiles=()
	for file in $files; do
		# [[ $VM_TEST != "" ]] && [[ -s "$srcDir/$file" ]] touch -m -t 200001010101 "$srcDir/$file"
		[[ -s "$srcDir/$file" ]] && validFiles+=($srcDir/$file)
	done

	git -C "$srcDir" restore $(git -C "$srcDir" ls-files $files 2>/dev/null | xargs) || git -C "$srcDir" restore .
	if [[ $VM_TEST == "" ]]; then
		echo "$(git -C $srcDir status -s -- ':!debian')" >> $LOG_FILE
	else
		remoteSh 'git -C linux status -s -- ':!debian''
	fi

	if isKernelBuildClean; then
		touch -m -t 200001010101 ${validFiles[*]}
		touch "$srcDir/vmlinux"
		touch "$srcDir/Makefile"
	fi
}

testId()
{
	local kernelVersion=$1
	local test=$2
	echo $test-$TEST_PLATFORM-${kernelVersion//\//_}
}

function runTests()
{
	local kernelVersions=$@
	local res=0

	# Restore all files that are used in tests
	for kernelVersion in $kernelVersions; do
		local srcDir=$(sourceDir $kernelVersion)
		local files=()
		for test in "${!Tests[@]}"; do
			for file in $(bash test/tests/$test/$test.sh --files); do
				[[ ! " ${files[*]} " =~ " ${file} " ]] && files+=($file)
			done
		done
		git -C "$srcDir" restore $(git -C "$srcDir" ls-files "${files[@]}" 2>/dev/null | xargs)
	done

	# Run tests
	for kernelVersion in $kernelVersions; do
		local rebuildKernel=1

		CURRENT_CROS_KERNEL_VERSION=$(crosKernelVersion $kernelVersion)

		for test in "${!Tests[@]}"; do
			local testScript=test/tests/$test/$test.sh
			local desc=$(bash $testScript --description)
			export TEST_ID=$(testId $kernelVersion $test)
			export CURRENT_TEST=$test
			exportVars $kernelVersion

			if grep -q "\b$TEST_ID\b" test/logs/pass_test > /dev/null 2>&1; then
				echo "Skip '$desc' on kernel $kernelVersion"
				continue
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
				[[ $res != 0 ]] && continue
			fi

			if [[ "$skipPrepareKernelAndDeploy" != 1 ]]; then
				if [[ "$rebuildKernel" == 1 ]]; then
					if grep -q "\bdekuDeploy\b" $testScript; then
						logStep "Prepare, build and deploy kernel $kernelVersion"
						prepareKernelAndDeploy $kernelVersion
						res=$?
						[[ $res != 0 ]] && continue
					else
						logStep "Prepare and build kernel $kernelVersion"
						prepareKernelAndBuild $kernelVersion
						res=$?
						[[ $res != 0 ]] && continue
					fi
					rebuildKernel=
				fi
				if grep -q "\bdekuDeploy\b" $testScript; then
					runQemu $kernelVersion
					res=$?
					[[ $res != 0 ]] && continue
				fi
			fi

			cp -f $(kernelConfigFile) /tmp/deku_test_config.backup
			bash $testScript --kernel $kernelVersion
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
		done
	done

	return $res
}

main()
{
	local run_base_tests=
	local run_lts_tests=
	local kernVer=$KERNEL_VERSION
	local cont=
	local rerun=

	mkdir -p test/logs/pass
	[[ $EXIT_ON_FAILURE ]] && logWarn "Exit on failure"

	while [[ $# -gt 0 ]]; do
		case $1 in
			# --all)
			# run_base_tests=1
			# run_lts_tests=1
			# export CHROMEOS=1
			# . test/common.sh 2>/dev/null
			# logInfo "Run all test"
			# shift
			# ;;
			--base)
			run_base_tests=1
			export TEST_PLATFORM=base
			logInfo "Run base test"
			shift
			;;
			--chromebook)
			export CHROMEOS=1
			export TEST_PLATFORM=cros
			logInfo "Run test on Chromebook"
			. test/common.sh 2>/dev/null
			shift
			;;
			--lts)
			run_lts_tests=1
			export TEST_PLATFORM=baseLTS
			logInfo "Run tests on LTS and recent kernel versions"
			shift
			;;
			--vm)
			export VM_TEST=1
			export TEST_PLATFORM=vm
			logInfo "Run test on VM"
			. test/common.sh 2>/dev/null
			KERNEL_VERSION="v6.8"
			shift
			;;
			--test)
			test=$2
			logInfo "Run $test test"
			addTest $test
			shift
			shift
			;;
			--system)
			logInfo "Run on $2"
			shift
			shift
			;;
			--kernel)
			kernVer=$2
			logInfo "Run on $kernVer"
			shift
			shift
			;;
			--index)
			index=$2
			logInfo "Test index: $index"
			export SSH_PORT_OFFSET=$index
			exportVars
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
			exportVars
			shift
			shift
			;;
			--testid)
			testId $kernVer $test
			exit 0
			;;
			--quick)
			QUICK_TEST=--quick
			logInfo "Run quick test"
			shift
			;;
			--continue)
			cont=1
			logInfo "Continue tests"
			shift
			;;
			--ssh)
			ssh root@localhost -p $SSH_PORT $SSHPARAMS
			exit 0
			;;
			-*|--*|*)
			echo "Unknown option $1"
			exit 1
			;;
		esac
	done

	if [[ "${!Tests[@]}" != "" ]]; then
		if [[ $run_lts_tests ]]; then
			if [[ $kernVer == "origin/master" ]]; then
				kernVer=$(git -C "$KERNELS_DIR/linux-stable" tag -l --sort=v:refname | tail -n 1)
			else
				kernVer=$(git -C "$KERNELS_DIR/linux-stable" tag -l --sort=v:refname | grep -F ${kernVer}. | tail -n 1)
			fi
		elif [[ $CHROMEOS ]]; then
			:
		fi
		export KERNEL_VERSION=$kernVer
	fi
	local srcDir=$(sourceDir $kernVer)

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

	if [[ ! $CHROMEOS$VM_TEST ]]; then
		if [[ ! -f "$ROOTFS_IMG" ]]; then
			logInfo "Rootfs image is not found. Generating..."
			pushd test
			sudo modprobe nbd
			sudo ./mkrootfs.sh
			popd
		fi
	fi

	if [[ $CHROMEOS == "" ]] && [[ $LOCAL_TEST == "" ]] && [[ $VM_TEST == "" ]]; then
		if [[ "$srcDir" == "" || ! -d "$srcDir" ]]; then
			logInfo "Can't find kernel sources dir $srcDir. Downloading..."
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

# make -C "$srcDir" mrproper
	if [[ "${!Tests[@]}" != "" ]]; then
		runTests $kernVer
		return
	fi

	[[ $CHROMEOS || $run_lts_tests ]] || run_base_tests=1
	[[ $cont == "" ]] && mv -f test/logs/pass_test /tmp 2>/dev/null
	[[ ! -e test/logs/pass_test ]] && rm -rf test/logs/*
	[[ -e test/logs/pass_test ]] && echo "----- $(date) -----" >> test/logs/pass_test
	[[ -e test/logs/failed_test ]] && echo "----- $(date) -----" >> test/logs/failed_test


	# if [[ $CHROMEOS == "" ]]; then
	# 	git -C "$CROS_SOURCE_DIR" diff --exit-code drivers/gpu/drm >/dev/null
	# 	[[ ${Tests["chromebook"]} != "" && $? != 0 && ! -e test/tests/chromebook/complited ]] &&
	# 		{ logErr "Kernel source dir in ChromiumOS SDK is not clear"; return 1; }

	# 	# make -C "$SOURCE_DIR" mrproper
	# 	[ ! -d "$SOURCE_DIR" ] && prepareKernelSources
	# fi

	if [[ $CHROMEOS ]]; then
		prepareLtsTests
		runTests v5.10 v5.15 v6.1 v6.6 v6.12 &
		bg_pids+=$!
	fi
	if [[ $run_lts_tests ]]; then
		prepareLtsTests
		srcDir=/usr/local/google/home/mmaslanka/linux-trees/linux-stable
		echo "$srcDir"
		local v5_10=$(git -C "$srcDir" tag -l --sort=v:refname | grep -F v5.10. | tail -n 1)
		local v5_15=$(git -C "$srcDir" tag -l --sort=v:refname | grep -F v5.15. | tail -n 1)
		local v6_1=$(git -C "$srcDir" tag -l --sort=v:refname | grep -F v6.1. | tail -n 1)
		local v6_6=$(git -C "$srcDir" tag -l --sort=v:refname | grep -F v6.6. | tail -n 1)
		local v6_12=$(git -C "$srcDir" tag -l --sort=v:refname | grep -F v6.12. | tail -n 1)
		runTests $v5_10 $v5_15 $v6_1 $v6_6 $v6_12 origin/master
	fi
	if [[ $run_base_tests ]]; then
		prepareTests
		if [[ $VM_TEST ]]; then
			runTests v6.8 v6.11
		else
			runTests $KERNEL_VERSION
		fi
	fi

	[[ ${Tests["chromebook"]} != "" ]] &&
		git -C /build/brya/var/cache/portage/sys-kernel/chromeos-kernel-$CHROMEOS_KERNEL_VER/source checkout drivers/gpu/drm/*

	trap 'for pid in ${bg_pids[*]}; do echo KILL $pid; kill -9 $pid; done; exit' INT

	for pid in ${bg_pids[*]}; do
		wait $pid
	done

	local failed=()

	[[ -s test/logs/failed_test ]] && while read -r line; do
		[[ $line == -----* ]] && continue
		line=${line%:*}
		grep -qwF $line test/logs/pass_test && continue
		[[ ! " ${failed[*]} " =~ " ${line} " ]] && failed+=("$line")
	done < test/logs/failed_test

	if [[ $failed == "" ]]; then
		echo -e "${GREEN}========== All tests passed successfully ==========${NC}"
		killall -q -9 "qemu-system-x86_64"
		local outFile="/tmp/test-$(date).tar.zstd"
		local exclude=
		[[ $CHROMEOS || $VM_TEST ]] || exclude="--exclude=\"test/rootfs.img\""
		tar --exclude=".git" --exclude="workdir_*" --exclude="test/tags/target" --exclude="doc" --exclude="*.zstd" $exclude -I "zstd -19" -cpf "$outFile" .
		mv "$outFile" .
	else
		echo -e "${ORANGE}========== Some tests failed ==========${NC}"
		printf "%s\n" "${failed[@]}"
		echo -e "${ORANGE}=======================================${NC}"
	fi
}

main $@
