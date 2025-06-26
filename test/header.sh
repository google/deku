# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku

# cache dir
export CACHE_DIR="$HOME/.cache/deku"

# default name for workdir
export DEFAULT_WORKDIR=workdir

# file with path to object file from kernel/module build directory
export FILE_OBJECT_PATH=obj

# file with source file path
export FILE_SRC_PATH=path

# DEKU script to reload modules
export DEKU_RELOAD_SCRIPT=deku_reload.sh

# log level filter
export LOG_LEVEL=1 # 0 - debug, 1 - info, 2 - warning, 3 - error

# colors
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export ORANGE='\033[0;33m'
export WHITE='\033[1;37m'
export NC='\033[0m' # No Color

# errors
export NO_ERROR=0
export ERROR_FORBIDDEN_MODIFY=25
export ERROR_DEPEND_MODULE_NOT_LOADED=43

# tests specific

export CROS_BOARD=brya

readonly KERNEL_VERSION_5_15="v5.15.165"
readonly KERNEL_VERSION_DEFAULT_BASE="v5.10.224"
readonly CHROMEOS_KERNEL_VER="5_15"

readonly SSHPARAMS_OPTIONS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlMaster=auto -o ControlPersist=300 -o BatchMode=yes"

readonly TEST_CACHE_DIR="$HOME/.cache/deku"
readonly ROOTFS_IMG=test/rootfs.img

readonly QEMU_SSH_KEY="test/testing_rsa"
readonly CROS_SSH_KEY="${CROS_WORKDIR}/testing_rsa"
readonly VM_SSH_KEY="test/testing_rsa"

readonly QEMU_SSH_PORT="60023"
readonly CROS_SSH_PORT="2244"
readonly VM_SSH_PORT="22220"

readonly QEMU_SOURCE_DIR="$TEST_CACHE_DIR/linux"
readonly CROS_SOURCE_DIR="/build/${CROS_BOARD}/var/cache/portage/sys-kernel/chromeos-kernel-$CHROMEOS_KERNEL_VER/source"
readonly VM_SOURCE_DIR="/tmp/deku-vm-mount/linux-6.8.4"

readonly QEMU_BUILD_DIR="$TEST_CACHE_DIR/build-linux-deku"
readonly CROS_BUILD_DIR="/build/${CROS_BOARD}/var/cache/portage/sys-kernel/chromeos-kernel-$CHROMEOS_KERNEL_VER"
readonly VM_BUILD_DIR="/tmp/deku-vm-mount/linux-6.8.4"

declare -g KERNEL_VERSION=$KERNEL_VERSION_DEFAULT_BASE

declare -g SCRIPT_NAME=$(basename "$0" .sh)
declare -g KERNEL_VER=
declare -g QUICK_TEST=
