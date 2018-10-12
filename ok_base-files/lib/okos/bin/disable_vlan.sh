#!/bin/sh

help()
{
    cat <<_HELP_
Disable an VLAN interface.
Usage: $0 [lan4053] VLANID

Example:
    $0 lan4053 100 # disable VLAN 100 on  port
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

if [ -n "${vid}" ]; then
    if [ $vid -ge 4096 -o $vid -le 0 ]; then
        help
        exit 1
    else
        ifx="${ifx}_${vid}"
        ifname="${ifname}.${vid}"
    fi
fi

echo $ifx $ifname
uci delete network.${ifx}

uci commit network
/etc/init.d/network reload

echo "VLAN interface $ifx is disabled."
exit 0
