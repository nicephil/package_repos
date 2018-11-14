#!/bin/sh

help()
{
    cat <<_HELP_
Setup WAN port on static ip mode.
Usage: $0 {wan|wan1|wan2} GATEWAY IPADDR/NETMASK[,IPADDR/NETMASK] DNS[,DNS]
        [-r IPADDR] [-m MTU] [-RS] 

        -r IPADDR # Add default route on this WAN port, and set IPADDR as primary IP.
        -m MTU # Set MTU on this interface
        -R # Don't add default route on this WAN port
        -S # don't restart service
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
    wan) ifx="$1";ifname="eth1";;
    wan1) ifx="$1";ifname="eth2";;
    wan2) ifx="$1";ifname="eth3";;
    *) help; exit 1;;
esac
gateway="$2"
ips="$3"
dnss="$4"
shift 4

defaultroute='0'
while [ -n "$1" ]; do
    case $1 in
        -r) defaultroute='1';src_ip="$2";shift 2;;
        -R) defaultroute='0';shift;;
        -m) mtu="$2";shift 2;;
        -S) no_restart='1';shift 1;;
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
uci set network.${ifx}.metric='100'

if [ -n "$mtu" ]; then
    uci set network.${ifx}.mtu=$mtu
fi

netmask=''
#uci delete network.${ifx}.ipaddr
#if [ $defaultroute = '1' ]; then
if [ -n "$src_ip" ]; then
    uci add_list network.${ifx}.ipaddr=$src_ip
fi
for ip in ${ips//,/ }; do
    OIFS=$IFS;IFS='/';set -- $ip;ipaddr=$1;netmask=$2;IFS=$OIFS
    if [ "$ipaddr" != "$src_ip" ]; then
        uci add_list network.${ifx}.ipaddr=$ipaddr
    fi
done
uci set network.${ifx}.netmask=$netmask

#uci delete network.${ifx}.dns
for dns in ${dnss//,/ }; do
    uci add_list network.${ifx}.dns=$dns
done

uci commit network

if [ -z "$no_restart" ]; then
    /etc/init.d/network reload
fi

#if [ $defaultroute = '1' ]; then
#    ip r add default dev $ifname via $gateway metric 1
#fi
echo "Set WAN port $ifx on static ip mode"
exit 0

