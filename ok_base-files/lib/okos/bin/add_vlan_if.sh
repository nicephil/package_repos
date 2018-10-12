#!/bin/sh

help()
{
    cat <<_HELP_
Create VLAN interface.
Usage: $0 [lan4053] VID
Example:
    $0 lan4053 100 # create vlan 100 on LAN port
_HELP_
}

if [ $# -lt 2 ]; then
    help
    exit 1
fi

case $1 in
    lan4053) ifx="$1";ifname="eth3";;
    *) help; exit 1;;
esac
vid="$2"
shift 2

while [ -n "$1" ]; do
    case $1 in
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

