#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

ln -fs /usr/share/zoneinfo/Europe/Warsaw /etc/localtime
apt update
apt install -y --no-install-recommends rsyslog kmod ssh \
			ifupdown iputils-ping network-manager wget \
			isc-dhcp-client vim
rm -rf /var/cache/apt

passwd -d root
mkdir -p ~/.ssh
ssh-keygen -b 4096 -f ~/.ssh/testing_rsa -N ""
cat ~/.ssh/testing_rsa.pub >> ~/.ssh/authorized_keys
mkdir deku
