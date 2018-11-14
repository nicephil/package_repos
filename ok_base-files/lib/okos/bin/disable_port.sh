#!/bin/sh

help()
{
    cat <<_HELP_
Disable an interface.
Usage: $0 {wan|wan1|wan2|lan} [-S]
        -S # don't restart service
Example:
    $0 wan # disable wan port
_HELP_
}

case "$1" in
    wan) ifx="$1";ifname="eth1";;
    wan1) ifx="$1";ifname="eth2";;
    wan2) ifx="$1";ifname="eth3";;
    lan) ifx="$1";ifname="eth0";;
    *) help; exit 1;;
esac
shift 1

while [ -n "$1" ]; do
    case $1 in
        -S) no_restart='1'; shift 1;;
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

if [ -z "$no_restart" ]; then
    /etc/init.d/network reload
fi

echo "Port $ifx is disabled."
exit 0

