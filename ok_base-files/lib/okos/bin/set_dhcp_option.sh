#!/bin/sh

help()
{
    cat <<_HELP_
Setup/Remove DHCP option on special dhcp pool

Usage: $0 {set|del} --option NUMBER --value STRING --pool POOL_ID [-S]
        --option NUMBER # option number [1,255]
        --value STRING # customed string
        --pool POOL_ID # use interface name temporarily
        -S # don't restart service
Example:
    $0 set --option 443 --value 192.168.1.3 --pool lan
_HELP_
}

case "$1" in
    set) cmd="$1";;
    del) cmd="$1";;
    *) help;exit 1;;
esac
shift 1

while [ -n "$1" ]; do
    case $1 in
        --option) option="$2";shift 2;;
        --value) value="$2";shift 2;;
        --pool) pool="$2";shift 2;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

[ -z "$option" -o -z "$value" -o -z "$pool" ] && help && exit 1

uci get dhcp.${pool} > /dev/null 2>&1
if [ "$?" != 0 ]; then
    echo "DHCP pool ${pool} doesn't exist."
    exit 2
fi

set_dhcp_option()
{
    echo "Add option ${option}:${value} on ${pool}"
    uci get dhcp.${pool}.dhcp_option | grep -e "\<${option},\"${value}\"\>" > /dev/null 2>&1
    if [ "$?" != 0 ]; then
        uci add_list dhcp.${pool}.dhcp_option="${option},\"${value}\""
    fi
}
del_dhcp_option()
{
    echo "Remove option ${option}:${value} on ${pool}"
    uci get dhcp.${pool}.dhcp_option | grep -e "\<${option},\"${value}\"\>" > /dev/null 2>&1
    if [ "$?" == 0 ]; then
        uci del_list dhcp.${pool}.dhcp_option="${option},\"${value}\""
    fi
}

case "$cmd" in
    set) set_dhcp_option;;
    del) del_dhcp_option;;
    *) help;exit 1;;
esac

uci commit dhcp

if [ -z "$no_restart" ]; then
    /etc/init.d/dnsmasq reload
fi

exit 0
