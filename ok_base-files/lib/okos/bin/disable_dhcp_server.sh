#!/bin/sh

help()
{
    cat <<_HELP_
Disable DHCP server on LAN port.
Usage: $0 [lan4053]
Example:
    $0 lan4053
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
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

uci set dhcp.${ifx}.ignore="1"
uci set dhcp.@dnsmasq[0].notinterface="wan wan1 wan2 ${ifx}"
uci commit dhcp

# need to update webui_config
uci set webui_config.${ifx}.dhcp_server_enable="0"
uci commit webui_config


/etc/init.d/dnsmasq restart
/etc/init.d/network reload

exit 0

