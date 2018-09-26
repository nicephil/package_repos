#!/bin/sh

if [ $# -ne 3 ]; then
    echo "Usage: $0 START LIMIT LEASE ( $0 1 200 83400 )"
    exit 1
fi

start="$1"
limit="$2"
leasetime="$3"

uci set dhcp.lan4053=dhcp
uci set dhcp.lan4053.interface='lan4053'
uci set dhcp.lan4053.start="${start}"
uci set dhcp.lan4053.limit="${limit}"
uci set dhcp.lan4053.leasetime="${leasetime}"

uci commit dhcp

/etc/init.d/dnsmasq restart

