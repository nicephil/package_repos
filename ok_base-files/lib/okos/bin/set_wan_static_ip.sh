#!/bin/sh

help()
{
    cat <<_HELP_
Setup WAN port on static ip mode.
Usage: $0 [wan|wan1|wan2] GATEWAY IPADDR/NETMASK[,IPADDR/NETMASK] DNS[,DNS]
        [-R] [-r IPADDRx]

        -r # Add default route on this WAN port
        -R # Don't add default route on this WAN port
Example:
    $0 wan 192.168.254.254 192.168.254.101/255.255.255.0,192.168.254.102/255.255.255.0,192.168.254.103/255.255.255.0 8.8.8.8,9.9.9.9 # set wan port with 3 ip addresses
    $0 wan1 172.16.139.254 172.16.139.250/255.255.255.0 8.8.8.8 -R # Set wan1 as static ip without default route.
    $0 wan2 10.1.1.1 10.1.1.3/255.255.255.0,10.1.1.5/255.255.255.0 114.114.114.114 -r 10.1.1.3 # Set wan2 as static ip with default route.
_HELP_
}


if [ $# -lt 4 ]; then
    help
    exit 1
fi

case $1 in
    wan) ifx="$1";ifname="eth0";;
    wan1) ifx="$1";ifname="eth1";;
    wan2) ifx="$1";ifname="eth2";;
    *) help; exit 1;;
esac
gateway="$2"
ips="$3"
dnss="$4"
shift 4

defaultroute='1'
while [ -n "$1" ]; do
    case $1 in
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

#echo $ifx $ips $dnss
uci delete network.${ifx}
uci set network.${ifx}='interface'
uci set network.${ifx}.ifname=$ifname
uci set network.${ifx}.proto='static'
uci set network.${ifx}.gateway=$gateway

netmask=''
#uci delete network.${ifx}.ipaddr
for ip in ${ips//,/ }; do
    OIFS=$IFS;IFS='/';set -- $ip;ipaddr=$1;netmask=$2;IFS=$OIFS
    #echo $ipaddr $netmask
    uci add_list network.${ifx}.ipaddr=$ipaddr
done
uci set network.${ifx}.netmask=$netmask

#uci delete network.${ifx}.dns
for dns in ${dnss//,/ }; do
    uci add_list network.${ifx}.dns=$dns
done

uci commit network
/etc/init.d/network reload

exit 0

