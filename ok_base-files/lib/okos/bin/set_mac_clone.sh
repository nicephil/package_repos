#!/bin/sh

help()
{
    cat <<_HELP_
Set mac address clone on wan interface.

Usage:  $0 {set|clr} {wan|wan1|wan2} [--mac-clone MAC] [-S]
        $0 set {wan|wan1|wan2} --mac-clone MAC [-S]
        $0 clr {wan|wan1|wan2} [-S]
        
        --mac-clone MAC # mac address of device
        -S # don't restart service

Example:
    $0 set wan2 --mac-clone 00:33:22:44:55:66
    $0 clr wan1
_HELP_
}


if [ $# -lt 2 ]; then
    help
    exit 1
fi

case "$1" in
    set) cmd="$1"; ifx="$2";;
    clr) cmd="$1"; ifx="$2";;
    *) echo "miss wan interface"; help; exit 2;;
esac
shift 2

while [ -n "$1" ]; do
    case $1 in
        --mac-clone) mac="$2";shift 2;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) echo "unknown option $1"; help;exit 3;;
        *) break;;
    esac
done

set_mac_clone()
{
    echo "set mac $mac clone on interface $ifx"
    uci set network.${ifx}.macaddr=$mac
}

clr_mac_clone()
{
    echo "clear mac clone on interface $ifx"
    uci del network.${ifx}.macaddr
}

case "$cmd" in
    set) set_mac_clone;;
    clr) clr_mac_clone;;
    *) help;exit 11;;
esac

uci commit network

if [ -z "$no_restart" ]; then
    /etc/init.d/network reload
fi

exit 0