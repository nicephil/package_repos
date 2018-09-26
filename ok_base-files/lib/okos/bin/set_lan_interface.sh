#!/bin/sh

if [ $# -ne 2 ]; then
    echo "Usage: $0 IPADDR NETMASK ( $0 172.16.254.254 255.255.255.0 )"
fi

#uci delete network.lan4053
#uci set network.lan4053=interface
#uci set network.lan4053.ifname='eth3'
#uci set network.lan4053.proto='static'
uci set network.lan4053.ipaddr='172.16.254.254'
uci set network.lan4053.netmask='255.255.255.0'
uci commit network

