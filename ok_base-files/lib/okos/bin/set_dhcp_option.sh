#!/bin/sh

help()
{
    cat <<_HELP_
Setup/Remove DHCP option on special dhcp pool

Usage: $0 ID --option NUMBER --value STRING --pool POOL_ID [-R] [-S]
        ID # use ID to identify each port mac ip address binding entry. 
           # Caller MUST ensure it's unique.
           # [a-zA-z][a-zA-Z0-9_]{,9}
        --option NUMBER # option number [1,255]
        --value STRING # customed string
        --pool POOL_ID # use interface name temporarily
        -R # remove this entry
        -S # don't restart service
Example:
    $0 101_1 --option 443 --value 192.168.1.3 --pool lan4053
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
        --option) option="$2";shift 2;;
        --value) value="$2";shift 2;;
        --pool) pool="$2";shift 2;;
        -R) remove='yes';shift 1;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

[ -z "$option" -o -z "$value" -o -z "$pool" ] && help && exit 1
uci get dhcp.${pool} > /dev/null 2&>1
if [ "$?" != 0 ]; then
    echo "DHCP pool ${pool} doesn't exist."
    exit 2
fi
if [ -z "$remove" ]; then
    echo "Add option ${option}:${value} on ${pool}"
    uci get dhcp.${pool}.dhcp_option | grep -e "\<${option},\"${value}\"\>" > /dev/null
    if [ "$?" != 0 ]; then
        uci add_list dhcp.${pool}.dhcp_option="${option},\"${value}\""
    fi
else
    echo "Remove option ${option}:${value} on ${pool}"
    uci get dhcp.${pool}.dhcp_option | grep -e "\<${option},${value}\>" > /dev/null
    if [ "$?" == 0 ]; then
        uci del_list dhcp.${pool}.dhcp_option="${option},\"${value}\""
    fi
fi

uci commit dhcp

if [ -z "$no_restart" ]; then
    /etc/init.d/dnsmasq reload
fi

exit 0