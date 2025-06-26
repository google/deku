#!/bin/bash

# Ensure the script is run with sudo
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Use sudo." >&2
  exit 1
fi

# Find the latest kernel version in /boot
latest_kernel=$(ls -t /boot/vmlinuz-* | head -n 1)

if [[ -z "$latest_kernel" ]]; then
  echo "No kernel found in /boot. Exiting." >&2
  exit 1
fi

# Extract the version from the filename
kernel_version=$(basename "$latest_kernel" | sed 's/vmlinuz-//')

# Update GRUB's default boot entry
echo "Updating GRUB to use kernel version: $kernel_version"
grub_entry="Advanced options for Ubuntu>Ubuntu, with Linux $kernel_version"

if [[ true ]]; then
	entry_id=$(grep "$kernel_version" /boot/grub/grub.cfg | grep menuentry | grep advanced | sed -r "s/.*'(gnulinux-.+)'.+/\1/")
	if [[ $entry_id == "" ]]; then
	  echo "Failed to find GRUB default entry. Ensure the kernel is correctly installed." >&2
	  exit 1
	fi
	sed -i "s/^GRUB_DEFAULT=.*/GRUB_DEFAULT='1>$entry_id'/" /etc/default/grub
else
	grub-set-default "$grub_entry"
fi

if [[ $? -ne 0 ]]; then
  echo "Failed to set GRUB default entry. Ensure the kernel is correctly installed." >&2
  exit 1
fi

# Update GRUB configuration
echo "Updating GRUB configuration..."
update-grub

echo "GRUB has been updated. The default kernel is now: $kernel_version"
