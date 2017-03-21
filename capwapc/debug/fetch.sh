rm -rf libservices_1.0-0_ar71xx.ipk
rm -rf capwapc_1_ar71xx.ipk
rm -rf libnmsc_1.0-0_ar71xx.ipk
opkg remove capwapc
opkg remove libnmsc
opkg remove libservices

scp llwang@192.168.254.118:/home/llwang/repos/osdk_repos/bin/ar71xx/packages/capwapc_1_ar71xx.ipk .
scp llwang@192.168.254.118:/home/llwang/repos/osdk_repos/bin/ar71xx/packages/libservices_1.0-0_ar71xx.ipk .
scp llwang@192.168.254.118:/home/llwang/repos/osdk_repos/bin/ar71xx/packages/libnmsc_1.0-0_ar71xx.ipk .

opkg install libservices_1.0-0_ar71xx.ipk
opkg install libnmsc_1.0-0_ar71xx.ipk
opkg install capwapc_1_ar71xx.ipk
