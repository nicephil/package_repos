#!/bin/sh

help()
{
    cat <<_HELP_
Setup mac ip entry binding.

Usage:  $0 {set|del} ID [--mac MAC] [--ip IPADDR] [--name NAME] [-S]
        $0 set ID --mac MAC --ip IPADDR [--name NAME] [-S]
        $0 del IP [-S]
        
        ID # use ID to identify each port mac ip address binding entry. 
           # Caller MUST ensure it's unique.
           # [a-zA-z][a-zA-Z0-9_]{,9}
        --mac MAC # mac address of device
        --ip IPADDR # ip address of device
        --name NAME # host name of device
        -S # don't restart service
Example:
    $0 chenyu01 --mac 00:33:22:44:55:66 --ip 192.168.1.5 --name "chenyu_pad"
_HELP_
}

case "$1" in
    set) cmd="$1";;
    del) cmd="$1";;
    *) help; exit 1;;
esac
shift 1

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

_del_mac_ip()
{
    uci get dhcp.${id} > /dev/null 2>&1
    if [ "$?" == 0 ]; then
        uci delete dhcp.${id}
    fi
}

set_mac_ip()
{
    _del_mac_ip

    [ -z "$mac" -o -z "$ip" ] && help && exit 1
    echo "Binding MAC ${mac} to IP $ip"
    uci set dhcp.${id}='host'
    uci set dhcp.${id}.mac="$mac"
    uci set dhcp.${id}.ip="$ip"
    #if [ -n "$name" ]; then
    #    uci set dhcp.${id}.name="$name"
    #fi
}
del_mac_ip()
{
    echo "Remove MAC binding <${id}>"
    _del_mac_ip
}

case "$cmd" in
    set) set_mac_ip;;
    del) del_mac_ip;;
    *) help;exit 1;;
esac

uci commit dhcp

if [ -z "$no_restart" ]; then
    /etc/init.d/dnsmasq reload
fi

exit 0