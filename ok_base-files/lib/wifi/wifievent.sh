#!/bin/sh

IFNAME=$1
EVENT=$2
CLIENT_MAC=$3

logger "=======> $*" 

case "$EVENT" in
        "AP-STA-CONNECTED")
                logger "=====>`hostapd_cli -p /var/run/hostapd-wifi${IFNAME:3:1} -i ${IFNAME} sta ${CLIENT_MAC}`"
                ;;
esac
