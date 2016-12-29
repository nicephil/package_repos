rm -rf libservices_1.0-0_ar71xx.ipk
rm -rf capwapc_1_ar71xx.ipk
opkg remove capwapc
opkg remove libservices

scp llwang@192.168.100.74:~/tmp/capwapc_1_ar71xx.ipk .
scp llwang@192.168.100.74:~/tmp/libservices_1.0-0_ar71xx.ipk .

opkg install libservices_1.0-0_ar71xx.ipk
opkg install capwapc_1_ar71xx.ipk
