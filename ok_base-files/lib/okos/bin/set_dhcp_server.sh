#!/bin/sh

help()
{
    cat <<_HELP_
Setup DHCP server on LAN port.
Usage: $0 [lan4053] START LIMIT [-l LEASE]
Example:
    $0 lan4053 1 200 -l 83400 
_HELP_
}

if [ $# -lt 3 ]; then
    help
    exit 1
fi

case $1 in
    lan4053) ifx="$1";ifname="eth3";;
    *) help; exit 1;;
esac
start="$2"
limit="$3"
shift 3

leasetime=83400
while [ -n "$1" ]; do
    case $1 in
        -l) leasetime="$2";shift 2;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

#uci delete dhcp.${ifx}
uci set dhcp.${ifx}=dhcp
uci set dhcp.${ifx}.interface="${ifx}"
uci set dhcp.${ifx}.start="${start}"
uci set dhcp.${ifx}.limit="${limit}"
uci set dhcp.${ifx}.leasetime="${leasetime}"
uci set dhcp.${ifx}.ignore="0"
uci set dhcp.@dnsmasq[0].notinterface="wan wan1 wan2"

uci commit dhcp
# need to update webui_config also
uci set webui_config.${ifx}.dhcp_start="${start}"
uci set webui_config.${ifx}.dhcp_limit="${limit}"
uci set webui_config.${ifx}.dhcp_leasetime="${leasetime}"
uci set webui_config.${ifx}.dhcp_server_enable="1"
uci commit webui_config

/etc/init.d/dnsmasq restart
exit 0


