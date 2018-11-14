#!/bin/sh

help()
{
    cat <<_HELP_
Setup DHCP server on LAN port.
Usage:  $0 {set|del} {lan} [--start START] [--limit LIMIT] [--lease LEASE] [--vid VLANID] [-S]
        $0 set {lan} --start START --limit LIMIT [--lease LEASE] [--vid VLANID] [-S]
        $0 del {lan} [--vid VLANID] [-S]
        --start START # the minimum address
        --limit LIMIT # the size of the address pool
        --lease LEASE # the lease time of addresses handed out to clients
        --vid VLANID # vlan id [1~4093] on the target interface
        -S # don't restart service
Example:
    $0 set lan 1 200 -l 83400 
_HELP_
}

case "$1" in
    set) cmd="$1";;
    del) cmd="$1";;
    *) help; exit 1;;
esac
shift 1

case $1 in
    lan) ifx="$1";ifname="eth0";;
    *) help; exit 1;;
esac
shift 1

leasetime=83400
while [ -n "$1" ]; do
    case $1 in
        --vid) vid="$2";shift 2;;
        --lease) leasetime="$2";shift 2;;
        --start) start="$2";shift 2;;
        --limit) limit="$2";shift 2;;
        -S) no_restart='1';shift 1;;
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

set_dhcp_pool()
{
    [ -n "$start" -a -n "$limit" ] || exit 1
    echo "Setup DHCP poll [${start},${limit}] on $ifx"

    uci set dhcp.${ifx}=dhcp
    uci get dhcp.common.interface | grep -e "\<${ifx}\>" > /dev/null 2>&1
    if [ "$?" != 0 ]; then
        uci add_list dhcp.common.interface="${ifx}"
    fi
    uci set dhcp.${ifx}.interface="${ifx}"
    uci set dhcp.${ifx}.networkid="${ifname}"
    uci set dhcp.${ifx}.start="${start}"
    uci set dhcp.${ifx}.limit="${limit}"
    uci set dhcp.${ifx}.leasetime="${leasetime}"
    uci set dhcp.${ifx}.ignore="0"
    if [ -z "$vid" ]; then
        # need to update webui_config also
        uci set webui_config.${ifx}.dhcp_start="${start}"
        uci set webui_config.${ifx}.dhcp_limit="${limit}"
        uci set webui_config.${ifx}.dhcp_leasetime="${leasetime}"
        uci set webui_config.${ifx}.dhcp_server_enable="1"
        uci commit webui_config
    fi
}

del_dhcp_pool()
{
    echo "Remove DHCP poll on $ifx"
    uci delete dhcp.${ifx} > /dev/null 2>&1
    uci del_list dhcp.common.interface="${ifx}" >/dev/null 2>&1
    if [ -z "$vid" ]; then
        # need to update webui_config
        uci set webui_config.${ifx}.dhcp_server_enable="0"
        uci commit webui_config
    fi
}

case "$cmd" in
    set) set_dhcp_pool;;
    del) del_dhcp_pool;;
    *) help; exit 1;;
esac

uci commit dhcp

if [ -z "$no_restart" ]; then
    /etc/init.d/dnsmasq restart
fi

exit 0


