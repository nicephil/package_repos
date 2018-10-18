#!/bin/sh

help()
{
    cat <<_HELP_
Setup mac ip entry binding.

Usage: $0 ID # use ID to identify each port mac ip address binding entry. Caller MUST ensure it's unique.
        ID # [a-zA-z][a-zA-Z0-9_]{,9}
        --mac MAC # mac address of device
        --ip IPADDR # ip address of device
        --name NAME # host name of device
        -R # remove this entry
        -S # don't restart service
Example:
    $0 chenyu01 --mac 00:33:22:44:55:66 --ip 192.168.1.5 --name "chenyu_pad"
_HELP_
}

if [ $# -lt 1 ]; then
    help
    exit 1
fi

echo 'Caller MUST ensure that ID is unique.'
id="$1"
shift 1

while [ -n "$1" ]; do
    case $1 in
        --mac) mac="$2";shift 2;;
        --ip) ip="$2";shift 2;;
        --name) name="$2";shift 2;;
        -R) remove='yes';shift 1;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

uci delete dhcp.${id}
if [ -z "$remove" ]; then
    [ -z "$mac" -o -z "$ip" ] && help && exit 1
    uci set dhcp.${id}='host'
    uci set dhcp.${id}.mac="$mac"
    uci set dhcp.${id}.ip="$ip"
    if [ -n "$name" ]; then
        uci set dhcp.${id}.name="$name"
    fi
fi

uci commit dhcp

if [ -z "$no_restart" ]; then
    /etc/init.d/dnsmasq reload
fi

exit 0