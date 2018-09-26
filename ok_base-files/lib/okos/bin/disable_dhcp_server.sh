#!/bin/sh

if [ $# -ne 0 ]; then
    echo "Usage: $0 <>"
    exit 1
fi

uci delete dhcp.lan4053
uci delete dhcp.lan4053.interface
uci delete dhcp.lan4053.start
uci delete dhcp.lan4053.limit
uci delete dhcp.lan4053.leasetime

uci commit network


/etc/init.d/dnsmasq restart
/etc/init.d/network reload



