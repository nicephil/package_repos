#!/bin/sh

help()
{
    cat <<_HELP_
Disable DHCP server on LAN port.
Usage: $0 [lan4053]
        -v VLANID # vlan id [1~4093] on the target interface
        -S # don't restart service
Example:
    $0 lan4053 -v 100 # disable dhcp server on vlan 100
_HELP_
}

if [ $# -lt 1 ]; then
    help
    exit 1
fi

case $1 in
    lan4053) ifx="$1";ifname="eth3";;
    *) help; exit 1;;
esac
shift 1

while [ -n "$1" ]; do
    case $1 in
        -v) vid="$2";shift 2;;
        -S) no_restart='1'; shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

if [ -n "${vid}" ]; then
    if [ $vid -ge 4096 -o $vid -le 0 ]; then
        help
        exit 1
    else
        ifx="${ifx}_${vid}"
        ifname="${ifname}.${vid}"
    fi
fi

if [ -z "$vid" ]; then
    uci set dhcp.${ifx}.ignore="1"
    #uci set dhcp.@dnsmasq[0].notinterface="wan wan1 wan2 ${ifx}"
else
    uci delete dhcp.${ifx}
fi
uci commit dhcp

if [ -z "$vid" ]; then
    # need to update webui_config
    uci set webui_config.${ifx}.dhcp_server_enable="0"
    uci commit webui_config
fi

if [ -z "$no_restart" ]; then
    /etc/init.d/network reload
    /etc/init.d/dnsmasq restart
fi

exit 0

