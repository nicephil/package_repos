#!/bin/sh

if [ $# -gt 2 -o $# -lt 1 ]; then
    echo "Usage: $0 INTERFACE [dnss] <$0 [wan|wan1|wan2] [8.8.8.8,9.9.9.9]>"
    exit 1
fi

ifx="$1"
dnss="$2"

uci set network.${ifx}.proto='dhcp'

uci delete network.${ifname}.dns
if [ -n "$dnss" ]; then
    for dns in ${dnss/,/ }; do
        uci add_list network.${ifname}.dns=$dns
    done
fi

uci commit network
/etc/init.d/network reload

exit 0

