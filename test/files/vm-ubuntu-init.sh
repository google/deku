#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku

mkdir ~/linux-trees
sudo mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 Public-mmaslanka ~/linux-trees/
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
git config --global gc.auto 0
git config --global --add safe.directory /home/test/linux-trees/ubuntu
mkdir -p linux
sudo sysctl -w kernel.dmesg_restrict=0
rm -rf linux/.git/index.lock