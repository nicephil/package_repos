#!/bin/sh

################################################################################
# README
#
# This script is used to prepare a gateway to real perform based on the image.
#
################################################################################

init ()
{
    opkg update
    opkg install ip tcpdump
}

reboot ()
{
    /etc/init.d/firewall stop
    /etc/init.d/firewall disable
    /etc/init.d/apfw stop
    /etc/init.d/apfw disable
    /etc/init.d/whitelist stop
    /etc/init.d/whitelist disable

    iptables -t nat -A POSTROUTING -o eth0.4090 -j MASQUERADE
}

case "$1" in
    init)
        init
        reboot
        ;;
    reboot)
        reboot
        ;;
    *)
        echo "Usage: $0 [init|cleanup]" && exit 1
        ;;
esac
