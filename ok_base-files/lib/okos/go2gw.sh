#!/bin/sh

################################################################################
# README
#
# This script is used to prepare a gateway to real perform based on the image.
#
################################################################################

export PATH="/lib/okos:$PATH"

opkg update
opkg install ip tcpdump

/etc/init.d/firewall stop
/etc/init.d/firewall disable

iptables -t nat -A POSTROUTING -o eth0.4090 -j MASQUERADE

