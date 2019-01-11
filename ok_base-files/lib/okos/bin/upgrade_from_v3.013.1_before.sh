#!/bin/sh

mount -o remount,sync /dev/loop0

sed -i 's/-z "$(rootfs_type)"/-n "$(rootfs_type)"/' /sbin/sysupgrade



cd /tmp
wget http://image.oakridge.vip:8000/images/x86_gw/sysloader/latest-sysupgrade.bin.tar.gz || exit
tar xvzf latest-sysupgrade.bin.tar.gz || exit

sysupgrade -v lede-x86-generic-combined-squashfs.img.gz

