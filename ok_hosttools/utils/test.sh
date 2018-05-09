#!/bin/sh

ip=$1

scp -r test_suit.py root@$1:/tmp/
scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/bin/ar71xx/packages/capwapc_1_ar71xx.ipk root@$1:/tmp/
scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/bin/ar71xx/packages/qca-hostapd-cli-10.4_g10600b1-dirty-1_ar71xx.ipk root@$1:/tmp/
scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/package_repos/ok_base-files/lib/okos/* root@$1:/lib/okos/.
scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/package_repos/ok_base-files/lib/wifi/hostapd.sh* root@$1:/lib/wifi/.
ssh root@$1 "opkg remove capwapc;opkg install /tmp/capwapc_1_ar71xx.ipk;/etc/init.d/capwapc restart;opkg remove qca-hostapd-cli-10.4;opkg install /tmp/qca-hostapd-cli-10.4_g10600b1-dirty-1_ar71xx.ipk"

