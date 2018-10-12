#!/bin/sh

help()
{
    cat <<_HELP_
Disable an interface.
Usage: $0 [wan|wan1|wan2|lan]

Example:
    $0 wan # disable wan port
_HELP_
}

if [ $# -lt 1 ]; then
    help
    exit 1
fi

case $1 in
    wan) ifx="$1";ifname="eth0";;
    wan1) ifx="$1";ifname="eth1";;
    wan2) ifx="$1";ifname="eth2";;
    lan4053) ifx="$1";ifname="eth3";;
    *) help; exit 1;;
esac
shift 1
while [ -n "$1" ]; do
    case $1 in
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

uci delete network.${ifx}
uci set network.${ifx}='interface'
uci set network.${ifx}.ifname=$ifname
uci set network.${ifx}.proto='none'
uci commit network
/etc/init.d/network reload

echo "Port $1 is disabled."
exit 0

