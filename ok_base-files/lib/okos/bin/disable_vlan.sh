#!/bin/sh

help()
{
    cat <<_HELP_
Disable an VLAN interface.
Usage: $0 [lan4053]
        -v VLANID # vlan id [1~4093] on the target interface
        -z ZONE [TRUSTED|UNTRUSTED|DMZ|GUEST] # assign security zone
        -S # don't restart service
Example:
    $0 lan4053 -v 100 # disable VLAN 100 on port
    $0 lan4053 # disable native VLAN on LAN port
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

vid=''
zone='TRUSTED'
while [ -n "$1" ]; do
    case $1 in
        -v) vid="$2";shift 2;;
        -z) zone="$2";shift 2;;
        -S) no_restart='1'; shift 1;;
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

case $zone in
    TRUSTED) zone_id='0';;
    UNTRUSTED) zone_id='1';;
    DMZ) zone_id='2';;
    GUEST) zone_id='3';;
    *) help; exit 1;;
esac

uci delete network.${ifx}
uci commit network

#uci del_list firewall.@zone[${zone_id}].network="${ifx}"
uci del_list firewall.${zone}.network="${ifx}"
uci commit firewall

if [ -z "$no_restart" ]; then
    /etc/init.d/network reload
    /etc/init.d/firewall reload
fi

echo "VLAN interface $ifx is disabled."
exit 0
