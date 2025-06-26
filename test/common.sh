#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Common functions for tests

# Functions return "0" as success

. test/header.sh

ARM64=
REMOTE_OUT=""
QEMU_PID=0
CURRENT_CROS_KERNEL_VERSION=

if [[ $ARM64 != "" ]]; then
	export ARCH=arm64
	export CROSS_COMPILE=aarch64-cros-linux-gnu-
fi

logDebug()
{
	echo "[DEBUG] $@" >> $LOG_FILE
	[[ "$LOG_LEVEL" > 0 ]] && return
	echo "[DEBUG] $@"
}
export -f logDebug

logInfo()
{
	if [[ $1 == "-e" ]]; then
		shift 1
		echo -e "$@" >> $LOG_FILE
	else
		echo "$@" >> $LOG_FILE
	fi
	[[ "$LOG_LEVEL" > 1 ]] && return

	if [[ $1 == "-e" ]]; then
		shift 1
		echo -e "$@"
	else
		echo "$@"
	fi
}
export -f logInfo

logWarn()
{
	echo "[WARN] $@" >> $LOG_FILE
	[[ "$LOG_LEVEL" > 2 ]] && return
	echo -e "$ORANGE$@$NC"
}
export -f logWarn

logErr()
{
	echo -e "[ERROR] $@" >> $LOG_FILE
	echo -e "$RED$@$NC" >&2
}
export -f logErr

logStep()
{
	if [[ $1 == "-n" ]]; then
		shift 1
		echo -n "$@" >> $LOG_FILE
		echo -e -n "$WHITE$@$NC"
	else
		echo "$@" >> $LOG_FILE
		echo -e "$WHITE$@$NC"
	fi
}
export -f logStep

filenameNoExt()
{
	local file=$1
	file=$(basename "$file")
	echo ${file%.*}
}
export -f filenameNoExt

generateModuleName()
{
	local file=$1
	LOG_ERR "WARNING! The 'generateModuleName' function is obsoleted!"
	# ./deku generateModuleName "$file"
}
export -f generateModuleName

appendToFunctionAt()
{
	local file=$1
	local line=$2
	local text=$3
	sed -i "$line,/{/ s/{/{\n\t$text/g" $file
}
export -f appendToFunctionAt

modifyFunctions()
{
	local file=$1
	local pass=$2
	logInfo "Modify file ($pass): $file"
	local out=`ctags -x -u --c-kinds=+p --fields=+afmikKlnsStz --extra=+q $file`
	local functions=`echo "$out" | grep function`
	[[ $functions == "" ]] && { logErr "No functions found in $file. Skip"; return; }
	local bckIFS=$IFS
	IFS=$'\n' functions=($functions)
	IFS=$bckIFS
	local count=${#functions[@]}
	local index=0
	[[ "$pass" == "0" ]] && index=0
	[[ "$pass" == "-1" ]] && index=$((count-1))
	[[ "$pass" == "-2" ]] && index=$((count/2))
	local funX=${functions[index]}
	local arr=($funX)
	appendToFunctionAt $file ${arr[2]} 'pr_err("DEKU");'
}
export -f modifyFunctions

appendToFunction()
{
	local file=$1
	local function=$2
	local text=$3
	logInfo "Append '$text' to function '$function' in file $file"
	test/tags/tags "mod_funcs" "$function" "$file" "$text"
}
export -f appendToFunction

appendBeforeFunction()
{
	local file=$1
	local function=$2
	local text=$3
	logInfo "Append '$text' before function '$function' in file $file"
	test/tags/tags "add_before_function" "$function" "$file" "$text"
}
export -f appendBeforeFunction

waitForSystemBootUp()
{
	[[ $LOCAL_TEST != "" || $TEST_ON_CHROMEBOOK != "" ]] && return 0

	for i in {1..60}; do
		if [[ $VM_TEST != "" ]]; then
			[ $(expr $i % 15) == 0 ] && logInfo "Waiting for VM..."

			ssh test@localhost -p $SSH_PORT $SSHPARAMS -o ConnectTimeout=1 -q "exit 0"
			if [[ $? == 0 ]]; then
				remoteSh "uname -a"
				find /tmp/deku-vm-mount -mindepth 1 -maxdepth 1 | read || sshfs -p $SSH_PORT $SSHPARAMS -o idmap=user -o cache=no test@localhost: /tmp/deku-vm-mount
				sync
				sleep 0.5
				find /tmp/deku-vm-mount -mindepth 1 -maxdepth 1 | read || continue
				copyToRemote test/update_grub.sh update_grub.sh
				copyToRemote test/files/vm-ubuntu-init.sh vm-ubuntu-init.sh
				remoteSh "bash vm-ubuntu-init.sh"
			else
				false
			fi
		elif [[ $CHROMEOS != "" ]]; then
			[ $(expr $i % 15) == 0 ] && logInfo "Waiting for DUT..."
			ssh -i /mnt/host/source/testing_rsa -p $CROS_SSH_PORT root@localhost -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 -q exit
		else
			[ $(expr $i % 15) == 0 ] && logInfo "Waiting for QEMU..."
			timeout --signal=SIGKILL 10 ssh root@localhost -p $SSH_PORT $SSHPARAMS -o ConnectTimeout=1 -q "rm -rf /var/log; exit"
		fi

		[[ $? == 0 ]] && return 0
		sleep 1
	done

	return 1
}

runQemu()
{
	local kernelVer=$1
	local buildDir=$BUILD_DIR
	[[ $kernelVer != "" ]] && buildDir=$(buildDir $kernelVer)
	local KERNEL_IMAGE="$buildDir/arch/x86/boot/bzImage"
	local cmdline="console=ttyS0 root=/dev/sda rw"
	local extraparams=
	local qemuexec="qemu-system-x86_64"
	local diskParam=
	local useVirtIO=1

	if [[ $useVirtIO != "" ]]; then
		# replace in cmdline "dev/sda" with "dev/vda"
		cmdline=${cmdline//dev\/sda/dev\/vda}
		diskParam="if=virtio,"
	fi

	if [[ $LOCAL_TEST != "" ]]; then
		return
	elif [[ $VM_TEST != "" ]]; then
		timeout --signal=SIGKILL 5 ssh test@localhost -p $SSH_PORT $SSHPARAMS -o ConnectTimeout=3 -q "ls -l"
		if [[ $? == 0 ]]; then
			ssh test@localhost -p $SSH_PORT $SSHPARAMS -o ConnectTimeout=3 -q "sudo reboot"
			waitForSystemBootUp && return
		fi

		for x in {1..3}; do
			fuser -k -n tcp $SSH_PORT
			pushd ~/Downloads/quickemu > /dev/null
			./quickemu --vm ubuntu-24.04.conf --ssh-port $SSH_PORT --public-dir ~/linux-trees --status-quo
			popd > /dev/null
			sleep 10
			waitForSystemBootUp && break
			logInfo "Seems that VM hung on launching. Restarting..."
		done

		rsync -rlt ../deku /tmp/deku-vm-mount/ --exclude "workdir_*" --exclude ".git" --exclude "test/rootfs.img" --exclude "test/" --exclude "test.mk" --exclude "test-*" --exclude "deku_*"
		remoteShOut "cd deku/; make clean; make"
		return
	elif [[ $CHROMEOS != "" ]]; then
		remoteSh "touch test || { /usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions 2; /usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions 4; reboot; }" > /dev/null 2>&1
		waitForSystemBootUp || { logErr "Chromebook didn't bootup"; return 1; }
		return
	fi

	[[ "$TEST_ON_CHROMEBOOK" ]] && return

	if [[ $ARM64 != "" ]]; then
		KERNEL_IMAGE="$buildDir/arch/arm64/boot/Image"
		cmdline="console=ttyAMA0 root=/dev/vda rw"
		extraparams="-M virt -cpu cortex-a72"
		qemuexec="qemu-system-aarch64"
	fi

	if [[ ! -f "$ROOTFS_IMG" ]]; then
		logInfo "Rootfs image is not found. Go to 'test' directory and run 'sudo ./mkrootfs.sh' to generate image."
		exit 1
	fi
	local logFile=$(logFile qemu)
	# TODO: Check if another qemu instance is not running
	fuser -k -n tcp $SSH_PORT
	local enablekvm="-enable-kvm"
	timeout 0.5 $qemuexec -nographic -enable-kvm > /dev/null 2>&1
	[[ $? == 1 ]] && enablekvm=

	for x in {1..3}; do
		# Wait a bit of time before start next instance of qemu
		sleep 0.5
		while true; do
			ps aux | grep "$SSH_PORT" | grep -q "qemu" && lsof -i:"$SSH_PORT" -Fp | grep -oP "p\K.*" | xargs kill -9
			sleep 0.2
			ps aux | grep "$SSH_PORT" | grep -q "qemu" && \
				logDebug "Waiting for close previous qemu instance" || break
			sleep 0.8
		done
		logInfo "Starting QEMU..."
		$qemuexec -kernel "$KERNEL_IMAGE" -drive ${diskParam}format=qcow2,file="$ROOTFS_IMG,snapshot=on" \
				-append "$cmdline" -serial file:$logFile -smp 4 -m 256 \
				-device virtio-net-pci,netdev=net0,romfile="" \
				-vnc none -netdev type=user,id=net0 \
				-nic "user,hostfwd=tcp::$SSH_PORT-:22" \
				-daemonize $enablekvm $extraparams
		QEMU_PID=$!
		waitForSystemBootUp && return
		logInfo "Seems that QEMU hung on launching. Restarting..."
	done
}
export -f runQemu

remoteSh()
{
	echo "SH: $@" >> $LOG_FILE

	if [[ $LOCAL_TEST != "" ]]; then
		local cmd="$@"
		REMOTE_OUT=$(bash -c "$cmd")
	elif [[ $CHROMEOS != "" ]]; then
		REMOTE_OUT=$(ssh -i /mnt/host/source/testing_rsa -p $CROS_SSH_PORT root@localhost -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=error "$@")
	elif [[ $VM_TEST != "" ]]; then
		REMOTE_OUT=$(ssh test@localhost -o LogLevel=error -p $SSH_PORT $SSHPARAMS "$@")
	else
		REMOTE_OUT=$(ssh root@localhost -o LogLevel=error -p $SSH_PORT $SSHPARAMS "$@")
	fi
	local res=${PIPESTATUS[0]}
	echo "$REMOTE_OUT" >> $LOG_FILE

 	return $res
}
export -f remoteSh

remoteShOut()
{
	remoteSh $@
	local ret=$?
	echo "$REMOTE_OUT"
	return $ret
}
export -f remoteShOut

runCmd()
{
	if [[ $LOCAL_TEST != "" ]]; then
		bash -c "$@" | tee -a $LOG_FILE
	elif [[ $CHROMEOS != "" ]]; then
		bash -c "$@" | tee -a $LOG_FILE
	elif [[ $VM_TEST != "" ]]; then
		remoteShOut "cd deku; $@"
	else
		docker run -t --network="host" -v ~/linux-trees:/kernel -v$(pwd):/deku -v /tmp:/tmp --workdir /deku deku_test:latest $@ | tee -a $LOG_FILE
	fi
}

copyToRemote()
{
	if [[ $LOCAL_TEST != "" ]]; then
		REMOTE_OUT=$(cp "$1" "$2")
	elif [[ $CHROMEOS != "" ]]; then
		REMOTE_OUT=$(scp -i /mnt/host/source/testing_rsa -P $CROS_SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$1" root@localhost:"$2")
	elif [[ $VM_TEST != "" ]]; then
		REMOTE_OUT=$(cp "$1" "/tmp/deku-vm-mount/$2")
	else
		REMOTE_OUT=$(scp -r -P $SSH_PORT $SSHPARAMS "$1" root@localhost:"$2")
	fi

	echo "$REMOTE_OUT" >> $LOG_FILE
	return ${PIPESTATUS[0]}
}
export -f remoteSh

function getLocalKernelDir
{
	home=$(eval echo ~${SUDO_USER})
	kernel_dir=$(find $home -maxdepth 1 -type d -name "linux-*")
	echo $kernel_dir
}
export -f getLocalKernelDir

sourceDir()
{
	local kernelVersion=$1

	if [[ $LOCAL_TEST != "" ]]; then
		getLocalKernelDir
	elif [[ $CHROMEOS != "" ]]; then
		[[ $kernelVersion != "" ]] && { echo "/mnt/host/source/src/third_party/kernel/$kernelVersion" ; return; }
		local kerndir=`find "$basedir/build/${CROS_BOARD}/var/db/pkg/sys-kernel/" -type f -name "chromeos-kernel-*"`
		kerndir=`basename $kerndir`
		kerndir=${kerndir%-9999*}
		local builddir="$basedir/build/${CROS_BOARD}/var/cache/portage/sys-kernel/$kerndir"
		readlink "$builddir/source"
	elif [[ $VM_TEST != "" ]]; then
		echo $SOURCE_DIR
	elif [[ $ARM64 != "" ]]; then
		echo "$KERNELS_DIR/arch64"
	else
		echo $KERNELS_DIR/$kernelVersion
	fi
}
export -f sourceDir

buildDir()
{
	local kernelVersion=$1

	if [[ $LOCAL_TEST != "" ]]; then
		getLocalKernelDir
	elif [[ $CHROMEOS != "" ]]; then
		[[ $kernelVersion != "" ]] && { echo "/mnt/host/source/src/third_party/kernel/$kernelVersion" ; return; }
		local kerndir=`find "$basedir/build/${CROS_BOARD}/var/db/pkg/sys-kernel/" -type f -name "chromeos-kernel-*"`
		kerndir=`basename $kerndir`
		kerndir=${kerndir%-9999*}
		local builddir="$basedir/build/${CROS_BOARD}/var/cache/portage/sys-kernel/$kerndir"
		echo "$builddir"
	elif [[ $VM_TEST != "" ]]; then
		echo $BUILD_DIR
	else
		local srcDir=$(sourceDir $kernelVersion)
		echo ${srcDir%/*}/build-${srcDir##*/}
	fi
}
export -f buildDir

prepareKernelSources()
{
	local kernelVersion=$1
	local srcDir=$(sourceDir $kernelVersion)

	[[ "$TEST_ON_CHROMEBOOK" || "$CHROMEOS" || "$LOCAL_TEST" ]] && return

	if [[ $VM_TEST != "" ]]; then
		# remoteSh "git clone -b master https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble linux-deku-test"
		return
	elif [[ $ARM64 != "" ]]; then
		git clone https://github.com/madvenka786/linux.git "$srcDir"
	else
		# git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git "$SOURCE_DIR"
		# versionShort=
		# versionLong=${kernelVersion}
		# if [[ $kernelVersion == "origin/master" ]]; then
		# 	versionShort="latest"
		# else if [[ $kernelVersion == v*.*.* ]]; then
		# 	# versionShort=${kernelVersion%.*}
		# 	versionShort=${kernelVersion}
		# else
		# 	versionShort=${kernelVersion}
		# 	versionLong=$(git -C "$KERNELS_DIR/linux-stable" tag -l --sort=v:refname | grep -F ${versionShort}. | tail -n 1)
		# fi
		# git -C $KERNELS_DIR/linux-stable archive --format=tar $versionLong | tar -x -C /kernel/$versionShort
		mkdir $srcDir
		git -C $KERNELS_DIR/linux-stable archive --format=tar $kernelVersion | tar -x -C $srcDir
		git -C $srcDir init
		git -C $srcDir add "*"
		git -C $srcDir commit --no-verify -m "Initial commit"
	fi
	mkdir -p "$BUILD_DIR"
}
export -f prepareKernelSources

workdirContainsOnly()
{
	local notcontains=()
	local modules=`find $WORKDIR -type d -name deku_*`
	for mod in "$@"; do
		[ ! -f "$WORKDIR/$mod/$mod.ko" ] && notcontains+="$mod  "
		modules=`sed "/^$WORKDIR\/$mod\$/d" <<< "$modules"`
	done
	[[ $modules != "" ]] && { >&2 echo -e "${RED}Workdir contains unexpected modules:$modules${NC}"; return 1; }
	[[ "$@" != "" && "$notcontains" != "" ]] && { >&2 echo -e "${RED}Workdir does not contains expected modules:${notcontains[@]}${NC}"; return 1; }
	[[ "$modules" != "" && "$notcontains" != "" ]] && return 1
	logInfo "Workdir contains only modules '$@'... OK"
}
export -f workdirContainsOnly

checkIfWorkdirIsEmpty()
{
	local workdirmodules=`find $WORKDIR -type d -name deku_*`
	[[ "$workdirmodules" != "" ]] && { logErr "Workdir must not contain any modules. Modules in workdir: $workdirmodules"; return 1; }
	logInfo "Workdir is empty... OK"
	return 0
}
export -f checkIfWorkdirIsEmpty

checkIfDmesgContains()
{
	local rc=0
	remoteSh dmesg
	for i in "$@"; do
		if ! grep -qF "$i" <<< "$REMOTE_OUT"; then
			logInfo "========================================================"
			logInfo "$REMOTE_OUT" | tail -n 100
			logInfo "========================================================"
			logErr "dmesg on remote does not contains:$i"
			rc=1
		fi
	done

	if ((rc == 0)); then
		for i in "$@"; do
			logInfo "dmesg contains: '$i'... OK"
		done
	fi
	return $rc
}
export -f checkIfDmesgContains

checkIfDmesgNOTContains()
{
	local rc=0
	remoteSh dmesg
	for i in "$@"; do
		if grep -qF "$i" <<< "$REMOTE_OUT"; then
			logInfo "========================================================"
			logInfo "$REMOTE_OUT"
			logInfo "========================================================"
			logErr "dmesg on remote contains unexpected:$i"
			rc=1
		fi
	done

	if ((rc == 0)); then
		for i in "$@"; do
			logInfo "dmesg not contains: '$i'... OK"
		done
	fi

	return $rc
}
export -f checkIfDmesgNOTContains

runCmdAndCheckIfDmesgContains()
{
	local cmd=$1
	local text=$2
# TODO: shift and $@
	for i in $(seq 1 20); do
		remoteSh $cmd
		checkIfDmesgContains "$text" > /dev/null 2>&1 && break
		sleep 1
	done
	checkIfDmesgContains "$text"
}
export -f runCmdAndCheckIfDmesgContains

checkIfFileExists()
{
	local file=$1
	[[ ! -f "$file" ]] && { logErr "File '$file' does not exists"; return 1; }
	logInfo "Found '$file'... OK"
	return 0
}
export -f checkIfFileExists

buildKernel()
{
	local extraparams=$1
	local logFile=$(logFile build)
	local srcDir=$(sourceDir $KERNEL_VER)
	local buildDir=$(buildDir $KERNEL_VER)

	[[ "$TEST_ON_CHROMEBOOK" ]] && return

	if [[ $LOCAL_TEST != "" ]]; then
		return
	elif [[ $CHROMEOS != "" ]]; then
		logInfo "Building the kernel..."
		remoteSh "touch test || { /usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions 2; /usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions 4; reboot; }" > /dev/null 2>&1 &
		USE="pcserial tty_console_ttyS0 livepatch" emerge-${CROS_BOARD} chromeos-kernel-$CURRENT_CROS_KERNEL_VERSION > $logFile 2>&1 || return 1
		for i in $(seq 1 10); do
			/mnt/host/source/src/scripts/update_kernel.sh --remote localhost --board=${CROS_BOARD} --clean --ssh_port $CROS_SSH_PORT >> $logFile 2>&1 && break
			logInfo "Re-run update the kernel"
		done
		return 0
	elif [[ $VM_TEST != "" ]]; then
		logInfo "Building the kernel..."
		# remoteShOut "cp -f /boot/config-\$(uname -r) linux-6.8.4/.config;" >> logFile 2>&1
		# remoteShOut "make $extraparams -C linux-6.8.4 mrproper" >> $logFile 2>&1
		# remoteShOut "yes '' | make $extraparams -C linux-6.8.4 oldconfig" >> $logFile 2>&1
		local cmd="
find . -maxdepth 1 \\( -name \"*.deb\" -o -name \"*_amd64.buildinfo\" -o -name \"*_amd64.changes\" \\) -delete;
time make $extraparams -C linux bindeb-pkg -j\$(nproc) 2>&1;
ls ./linux-image-*_amd64.deb 2>&1 > /dev/null || {
	>&2 echo \"Can't find any linux-image-*_amd64.deb files\";
	exit 1;
};
sudo apt install -y --allow-downgrades ./linux-image-*_amd64.deb ./linux-headers-*_amd64.deb 2>&1;
sudo ./update_grub.sh;
sudo ./update_grub.sh test;
		"
		remoteShOut "$cmd" > $logFile || { logErr "Fail to build kernel"; return 1; }
		return
	fi

	logInfo "Building the kernel..."
	# rm -f "$buildDir/vmlinux"
	yes "" | make $extraparams -C "$srcDir" O="$buildDir" oldconfig > $logFile 2>&1
	docker run -t -v ~/linux-trees:/kernel deku_test:latest make $extraparams -C "${srcDir##*/}" O="../${buildDir##*/}" -j`nproc` >> $logFile 2>&1
}
export -f buildKernel

enableKernelConfig()
{
	local flag=$1
	local action="--enable"
	[[ $2 != "" ]] && action=$2
	local srcDir="$(sourceDir $KERNEL_VER)"
	local config="$BUILD_DIR"/.config
	if [[ $CHROMEOS != "" ]]; then
		config="$srcDir/chromeos/config/chromeos/x86_64/chromeos-intel-pineview.flavour.config"
	fi
	"$srcDir/scripts/config" --file "$config" $action $flag
}
export -f enableKernelConfig

prepareKernel()
{
	local version=$1
	local usellvm=$2
	local extraparams=
	local srcDir=$(sourceDir $version)
	local buildDir=$BUILD_DIR
	[[ $version != "" ]] && buildDir=$(buildDir $version)

	if [[ $LOCAL_TEST != "" ]]; then
		local kernelDir=$(getLocalKernelDir)
		git -C $kernelDir reset --hard
		return
	elif [[ $CHROMEOS == "" ]]; then
		[[ $ARM64 != "" ]] && version="orc_v3"

		if [[ "$srcDir" == "" || ! -d "$srcDir" ]]; then
			logErr "Can't find kernel sources dir $srcDir"
			exit 1
		fi

		if [[ $VM_TEST != "" ]]; then
			# remoteSh "git -C linux-6.8.4 reset --hard"
			local tag=
			if [[ $version == v6.11 ]]; then
				tag="Ubuntu-hwe-6.11-6.11.0-17.17_24.04.2"
			else
				tag="Ubuntu-6.8.0-49.49"
			fi
			srcDir="\$HOME/linux"
			local currentTag=$(remoteShOut git -C $srcDir describe --exact-match --tags)
			[[ "$currentTag" != "$tag" ]] && echo "Remove old linux dir" && remoteSh "rm -rf $srcDir; mkdir $srcDir"
			local cmd="
if [ -z \"\$(ls -A $srcDir)\" ]; then
	echo 'Prepare kernel from $tag...';
	mkdir -p $srcDir;
	time GIT_INDEX_FILE=/tmp/git.index git --git-dir=\$HOME/linux-trees/ubuntu/.git --work-tree=$srcDir restore --source=$tag -- . &&
	cd $srcDir &&
	time git init 2>/dev/null &&
	time git add \"*\" >/dev/null &&
	time git commit --no-verify -m 'Initial commit' >/dev/null &&
	git tag $tag;
else
	cd $srcDir;
	echo 'Reset kernel dir';
	git clean -d -f;
	git reset --hard;
fi;
cd $srcDir;
make kernelversion;
cp -v /boot/config-\$(uname -r) .config;
yes '' | make oldconfig > /dev/null;
scripts/config --disable DEBUG_INFO;
scripts/config --disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT;
scripts/config --disable DEBUG_INFO_DWARF4;
scripts/config --disable DEBUG_INFO_DWARF5;
scripts/config --enable DEBUG_INFO_NONE;
scripts/config --disable SYSTEM_TRUSTED_KEYS;
scripts/config --disable SYSTEM_REVOCATION_KEYS;
scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS '';
scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS '';
"
			remoteShOut "$cmd" || { logErr "Fail to prepare kernel"; return 1; }

		else
			git -C "$srcDir" reset --hard
			git -C "$srcDir" clean -d -f
		fi

		[[ "$TEST_ON_CHROMEBOOK" ]] && return
		if [[ $VM_TEST == "" ]]; then
			git -C "$srcDir" reset --hard
			git -C "$srcDir" clean -d -f

			[[ "$usellvm" == "llvm" ]] && extraparams="CC=clang"
			[[ $version != "" ]] && export KERNEL_VER=$version
			make $extraparams -C "$srcDir" O="$buildDir" defconfig >/dev/null
			sed -i s/=m/=y/g "$buildDir/.config"
			enableKernelConfig FRAME_POINTER_VALIDATION
			enableKernelConfig FTRACE
			enableKernelConfig KALLSYMS_ALL
			enableKernelConfig FUNCTION_TRACER
			enableKernelConfig LIVEPATCH
			# enableKernelConfig DEBUG_INFO
			# enableKernelConfig GDB_SCRIPTS
			enableKernelConfig BT --module
		fi
	fi

	shift 1
	for cfg in "$@"
	do
		if [[ "$cfg" == +* ]]; then
			cfg="${cfg:1}"
			logInfo "Enable $cfg as a module"
			enableKernelConfig $cfg --module
		elif [[ "$cfg" == -* ]]; then
			cfg="${cfg:1}"
			logInfo "Disable $cfg"
			enableKernelConfig $cfg --disable
		else
			logInfo "Enable $cfg"
			enableKernelConfig $cfg
		fi
	done

}
export -f prepareKernel

prepareKernelAndBuild()
{
	local usellvm=$2
	local extraparams=
	[[ "$usellvm" == "llvm" ]] && extraparams="CC=clang"
	prepareKernel $@
	buildKernel "$extraparams"
}
export -f prepareKernelAndBuild

initDEKU()
{
	if [[ "$TEST_ON_CHROMEBOOK" ]]; then
		initDEKUForChromebook $@
		return
	fi
	rm -rf "$WORKDIR"
}
export -f initDEKU

initDEKUForChromebook()
{
	local mode=$1
	[[ $mode == "no_init" ]] && return

	rm -rf "$WORKDIR"
	./deku --workdir="$WORKDIR" --board=$CROS_BOARD build
}
export -f initDEKU

compareFileContents()
{
	local file=$1
	local expected=$2
	local got=$(<$file)
	if [[ $expected != $got ]]; then
		logErr "Unexpected contents of file: $file"
		logInfo "================== EXPECTED =================="
		logInfo -e "${expected}"
		logInfo "=============================================="
		logInfo ""
		logInfo "===================== GOT ===================="
		logInfo -e "${got}"
		logInfo "=============================================="
		logInfo ""
		return 1
	fi
	logInfo "Contents of file $file is... OK"
	return 0
}
export -f appendToFunctionAt

clearLogs()
{
	[[ $VM_TEST ]] && remoteSh "sudo dmesg -C" && return
	remoteSh "dmesg -C"
}

logFile()
{
	local fileSufix=$1
	# local test=$1
	# local kernelVer=$2

	# if [[ $test == "" ]]; then
	# 	test=${0##*/}
	# 	test="${test%%.*}"
	# fi
	# [[ $kernelVer == "" ]] && kernelVer=$KERNEL_VER
	# kernelVer=${kernelVer//\//_}

	# echo test/logs/$test-$kernelVer.log
	[[ $fileSufix != "" ]] && fileSufix="-"$fileSufix
	echo test/logs/$TEST_ID$fileSufix.log
}

dekuBuild()
{
	local logFile=$(logFile build)
	local out=
	local printOut=
	if [[ $1 == "--log" ]]; then
		printOut=1
		shift
	fi

	if [[ $LOCAL_TEST != "" ]]; then
		local kernelDir=$(getLocalKernelDir)
		out=$(./deku --workdir="$WORKDIR" \
					 -b $kernelDir \
					  $@ \
					  livepatch 2>&1)
	elif [[ "${TEST_ON_CHROMEBOOK}" != "" || "${CHROMEOS}" != "" ]]; then
		out=$(./deku --workdir="$WORKDIR" --board=${CROS_BOARD} \
					 $@ \
					 livepatch 2>&1)
	elif [[ $VM_TEST != "" ]]; then
		out=$(remoteShOut "cd deku; ./deku --workdir=workdir_test \
					 --builddir=../linux \
					 $@ \
					 livepatch 2>&1")
	else
		out=$(docker run -t --network="host" -v ~/linux-trees:/kernel -v$(pwd):/deku -v /tmp:/tmp --workdir /deku deku_test:latest \
			./deku -v --workdir="$WORKDIR" \
					 --builddir="/kernel/${BUILD_DIR##*/}" \
					 $@ \
					 livepatch 2>&1)
	fi

	res=$?
	echo "$out" >> $logFile
	[[ $printOut ]] && echo "$out"
	return $res
}
export -f dekuBuild

dekuDeploy()
{
	local logFile=$(logFile)
	local out=
	local printOut=
	if [[ $1 == "--log" ]]; then
		printOut=1
		shift
	fi

	if [[ $LOCAL_TEST != "" ]]; then
		local kernelDir=$(getLocalKernelDir)
		out=$(./deku --workdir="$WORKDIR" \
					 --builddir=$kernelDir \
					 $@ 2>&1)
	elif [[ "${TEST_ON_CHROMEBOOK}" != "" || "${CHROMEOS}" != "" ]]; then
		out=$(./deku --workdir="$WORKDIR" \
					 --target="$DEPLOY_PARAMS" \
					 $@ 2>&1)
	elif [[ $VM_TEST != "" ]]; then
		out=$(remoteShOut "cd deku; ./deku --workdir=workdir_test \
					 --builddir=../linux \
					 $@" 2>&1)
	else
	logInfo ./deku -v --workdir="$WORKDIR" \
					 --builddir="/kernel/${BUILD_DIR##*/}" \
			   		 --target="$DEPLOY_PARAMS" --ssh_options="${SSHPARAMS}"
		out=$(docker run -t --network="host" -v ~/linux-trees:/kernel -v$(pwd):/deku -v /tmp:/tmp --workdir /deku deku_test:latest \
			./deku --workdir="$WORKDIR" \
				   --builddir="/kernel/${BUILD_DIR##*/}" \
			   	   --target="$DEPLOY_PARAMS" --ssh_options="${SSHPARAMS}" \
				   $@ 2>&1)
	fi

	res=$?
	echo "$out" >> $logFile
	[[ $printOut ]] && echo "$out"
	return $res
}
export -f dekuDeploy

revertChanges()
{
	local srcDir=$(sourceDir $KERNEL_VER)

	git -C "$srcDir" restore $(git -C "$srcDir" ls-files $FILES 2>/dev/null | xargs)

	if [[ $VM_TEST == "" ]]; then
		echo "$(git -C $srcDir status -s -- ':!debian')" >> $LOG_FILE
	else
		remoteSh 'git -C linux status -s -- ':!debian''
	fi
}

exitError()
{
	local code=$1
	if [[ $code == "" ]]; then
		if [ -n "$ZSH_VERSION" ]; then
			code=$LINENO
		else
			code=${BASH_LINENO[0]}
		fi
	fi

	exit $code
}

function crosKernelVersion()
{
	local version=$1
	[[ $version == "v5.10" ]] && version="5_10"
	[[ $version == "v5.15" ]] && version="5_15"
	[[ $version == "v6.1" ]] && version="6_1"
	[[ $version == "v6.6" ]] && version="6_6"
	[[ $version == "v6.12" ]] && version="6_12"

	echo $version
}
export -f crosKernelVersion

exportVars()
{
	local PREFIX=QEMU
	if [[ "${TEST_ON_CHROMEBOOK}" != "" || "${CHROMEOS}" != "" ]]; then
		PREFIX=CROS
	elif [[ $VM_TEST ]]; then
		PREFIX=VM
	fi

	local L_SSH_PORT=${PREFIX}_SSH_PORT
	local SOURCE_DIR=${PREFIX}_SOURCE_DIR
	local BUILD_DIR=${PREFIX}_BUILD_DIR
	local SSH_KEY=${PREFIX}_SSH_KEY

 	L_SSH_PORT=${!L_SSH_PORT}
	[[ $SSH_PORT_OFFSET != "" ]] && L_SSH_PORT=$((L_SSH_PORT+SSH_PORT_OFFSET))
	[[ $SSH_PORT_OVERRIDE != "" ]] && L_SSH_PORT=$SSH_PORT_OVERRIDE
	export SSH_PORT=${L_SSH_PORT}

	SSH_KEY="${!SSH_KEY}"

	declare -g SSHPARAMS="${SSHPARAMS_OPTIONS} -o IdentityFile=$SSH_KEY"
	declare -g DEPLOY_PARAMS="root@localhost:${L_SSH_PORT}"

	declare -g LOG_FILE=$(logFile)

	export WORKDIR="workdir_$TEST_ID"
	if [[ $VM_TEST ]]; then
		export WORKDIR="/tmp/deku-vm-mount/deku/workdir_test"
	fi

	local kernelVer=$1
	if [[ $kernelVer != "" ]]; then
		SOURCE_DIR="${!SOURCE_DIR}"
		BUILD_DIR="${!BUILD_DIR}"
		declare -g BUILD_DIR=$(buildDir $kernelVer)
		declare -g SOURCE_DIR=$(sourceDir $kernelVer)
	else
		export SOURCE_DIR="${!SOURCE_DIR}"
		export BUILD_DIR="${!BUILD_DIR}"
	fi
}

parseArgs()
{
	POSITIONAL_ARGS=()

	while [[ $# -gt 0 ]]; do
		case $1 in
			--files)
			echo "$FILES"
			exit 0
			;;
			--description)
			echo "$DESCRIPTION"
			exit 0
			;;
			--kernel)
			KERNEL_VER="$2"
			export BUILD_DIR=$(buildDir $KERNEL_VER)
			export SOURCE_DIR=$(sourceDir $KERNEL_VER)
			shift # past argument
			shift # past value
			;;
			--capsKernel)
			echo "$KERNEL"
			exit 0
			;;
			--quick)
			QUICK_TEST=1
			shift # past argument
			;;
			*)
			POSITIONAL_ARGS+=("$1") # save positional arg
			shift # past argument
			;;
		esac
	done

	if [[ $CHROMEOS != "" ]]; then
		CURRENT_CROS_KERNEL_VERSION=$(crosKernelVersion $KERNEL_VER)
	fi

	set -- "${POSITIONAL_ARGS[@]}"
}

parseArgs $@
exportVars
