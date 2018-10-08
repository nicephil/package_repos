#!/bin/sh

if [ $# -ne 4 ]; then
    echo "Usage: $0 [wan|wan1|wan2] GATEWAY \"IPADDR/NETMASK\"[;\"IPADDR/NETMASK\"] [DNS,DNS] ( $0 wan 192.168.254.254 \"172.16.254.102/255.255.255.0,172.16.254.103/255.255.255.0\" \"8.8.8.8,9.9.9.9\" )"
    exit 1
fi

ifname="$1"
gateway="$2"
ips="$3"
dnss="$4"

echo $ifname $ips $dnss
uci set network.${ifname}.proto='static'
uci set network.${ifname}.gateway=$gateway

netmask=''
uci delete network.${ifname}.ipaddr
for ip in ${ips/,/ }; do
    OIFS=$IFS;IFS='/';set -- $ip;ipaddr=$1;netmask=$2;IFS=$OIFS
    uci add_list network.${ifname}.ipaddr=$ipaddr
done
uci set network.${ifname}.netmask=$netmask

uci delete network.${ifname}.dns
for dns in ${dnss/,/ }; do
    uci add_list network.${ifname}.dns=$dns
done

uci commit network
/etc/init.d/network reload

exit 0

