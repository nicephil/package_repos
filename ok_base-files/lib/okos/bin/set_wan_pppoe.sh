#!/bin/sh

help()
{
    cat <<_HELP_
Setup WAN port on PPPOE mode.
Usage: $0 [wan|wan1|wan2] USERNAME PASSWORD
        [-k KEEPALIVE] [-d DNS[,DNS]] [-Gg]
        -k KEEPALIVE # How many unreceived echo will trigger reconnection. Echo will be sent for every 5 seconds.
        -d DNS[,DNS] # Manually add dns list
        -r # Add default route on this WAN port, it's default behavior.
        -R # Don't add default route on this WAN port
        -m MTU # Set MTU on this interface
        -S # don't restart service
Example:
    $0 wan hzhz804352 oakridge -k 3 -d '8.8.8.8,9.9.9.9'
    $0 wan1 hzhz804352 oakridge -R # Set wan1 as pppoe without default route.
    $0 wan2 hzhz804352 oakridge -r # Set wan2 as pppoe with default route, it's default behavior.
_HELP_
}

if [ $# -lt 3 ]; then
    help
    exit 1
fi

case $1 in
    wan) ifx="$1";ifname="eth0";;
    wan1) ifx="$1";ifname="eth1";;
    wan2) ifx="$1";ifname="eth2";;
    *) help; exit 1;;
esac
username="$2"
password="$3"
shift 3

keepalive=''
dnss=''
defaultroute='1'
mtu=''
while [ -n "$1" ]; do
    case $1 in
        -k) keepalive="$2";shift 2;;
        -d) dnss="$2";shift 2;;
        -R) defaultroute='0';shift 1;;
        -r) defaultroute='1';shift 1;;
        -m) mtu="$2";shift 2;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

uci delete network.${ifx}
uci set network.${ifx}='interface'
uci set network.${ifx}.ifname=$ifname
uci set network.${ifx}.proto='pppoe'
uci set network.${ifx}.username=$username
uci set network.${ifx}.password=$password

if [ -n "$mtu" ]; then
    uci set network.${ifx}.mtu=$mtu
fi

if [ -n "$keepalive" ]; then
    uci set network.${ifx}.keepalive=$keepalive
fi

uci set network.${ifx}.defaultroute=$defaultroute

#uci delete network.${ifname}.dns
if [ -n "$dnss" ]; then
    for dns in ${dnss//,/ }; do
        uci add_list network.${ifname}.dns=$dns
    done
fi

uci commit network

if [ -z "$no_restart" ]; then
    /etc/init.d/network reload
fi

#if [ $defaultroute = '1' ]; then
#    ip r add default dev $ifname metric 1
#fi

exit 0

