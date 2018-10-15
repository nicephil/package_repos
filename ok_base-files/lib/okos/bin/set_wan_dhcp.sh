#!/bin/sh

help()
{
    cat <<_HELP_
Setup WAN port on DHCP mode.
Usage: $0 [wan|wan1|wan2] [-d DNS[,DNS]] [-Gg]
        -d DNS[,DNS] # Manually add dns list
        -r # Add default route on this WAN port, It's default behavior.
        -R # Don't add default route on this WAN port
        -m MTU # Set MTU on this interface
        -S # don't restart service
Example:
    $0 wan # Set port 'wan' as dhcp mode.
    $0 wan1 -d 8.8.8.8,9.9.9.9 # Set port 'wan' as dhcp mode with manual DNS settings.
    $0 wan -R # Set port 'wan' as dhcp mode, but don't set default route on it.
_HELP_
}


if [ $# -lt 1 ]; then
    help
    exit 1
fi

case $1 in
    wan) ifx="$1";ifname="eth0";;
    wan1) ifx="$1";ifname="eth1";;
    wan2) ifx="$1";ifname="eth2";;
    *) help; exit 1;;
esac
shift 1

dnss=""
defaultroute='1'
mtu=''
while [ -n "$1" ]; do
    case $1 in
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
uci set network.${ifx}.proto='dhcp'
uci set network.${ifx}.defaultroute=$defaultroute

if [ -n "$mtu" ]; then
    uci set network.${ifx}.mtu=$mtu
fi

#uci delete network.${ifx}.dns
if [ -n "$dnss" ]; then
    for dns in ${dnss/,/ }; do
        uci add_list network.${ifx}.dns=$dns
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

