#!/bin/sh

scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/master_for_BB-14.07/osdk_repos/package_repos/ok_base-files/lib/* /lib/.
scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/master_for_BB-14.07/osdk_repos/package_repos/ok_base-files/sbin/* /sbin/.
scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/master_for_BB-14.07/osdk_repos/package_repos/ok_base-files/etc/* /etc/.
scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/master_for_BB-14.07/osdk_repos/package_repos/luci/modules/okos-webui/luasrc/controller/okos/index.lua /usr/lib/lua/luci/controller/okos/index.lua
rm -rvf /tmp/luci*
