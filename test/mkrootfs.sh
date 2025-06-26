#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku

ARM64=

# Inside cros_sdk
# wget https://github.com/multiarch/qemu-user-static/releases/download/v7.2.0-1/qemu-aarch64-static
# cp qemu-aarch64-static /mnt/host/source/chromite/bin/

echo "Download rootfs image"
arch="amd64"
[[ $ARM64 != "" ]] && arch="arm64"
curl https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.2-base-${arch}.tar.gz -o ubuntu-base.tar.gz

echo "Make qcow2 image"
qemu-img create -f qcow2 rootfs.qcow2 800M
# sudo modprobe nbd
sudo qemu-nbd --connect=/dev/nbd0 rootfs.qcow2

# Format the qcow2 disk while connected as nbd
sudo mkfs.ext4 -F -L dekutestroot /dev/nbd0

mkdir rootfs

echo "Mount rootfs"
# sudo qemu-nbd --connect=/dev/nbd0 rootfs.qcow2
sudo mount /dev/nbd0 rootfs

echo "Prepare rootfs"
sudo tar zxvf ubuntu-base.tar.gz -C rootfs
sudo cp -rf rootfs-overlay/* rootfs/
sudo mount -t proc /proc rootfs/proc
sudo mount -t sysfs /sys rootfs/sys
sudo mount -o bind /dev rootfs/dev
sudo mount -o bind /dev/pts rootfs/dev/pts

echo "Enter to chroot"
if [[ $ARM64 != "" ]]; then
    cp "$(which qemu-aarch64-static)" rootfs/usr/bin
    sudo chroot rootfs qemu-aarch64-static /bin/bash /root/install.sh
else
    sudo chroot rootfs /bin/bash /root/install.sh
fi

echo "Exited from chroot"

echo "Copy SSH keys"
cp rootfs/root/.ssh/testing_rsa .
cat /home/${SUDO_USER}/.ssh/id_ed25519.pub >> rootfs/root/.ssh/authorized_keys

echo "Unmount"
sudo umount rootfs/proc
sudo umount rootfs/sys
sudo umount rootfs/dev/pts
sudo umount rootfs/dev
sudo umount rootfs
sudo qemu-nbd --disconnect /dev/nbd0

# Resize directly
sudo qemu-img resize rootfs.qcow2 +100M

echo "Fix ownership"
chown $SUDO_USER testing_rsa
chown $SUDO_USER rootfs.qcow2

echo "Cleanup"
rm -rf rootfs
rm ubuntu-base.tar.gz
