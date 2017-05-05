#!/bin/sh

IFNAME=$1
EVENT=$2
CLIENT_MAC=$3

logger -t hostapd_cli "=======>$*" 

/lib/wifi/updatestainfo.sh $IFNAME $CLIENT_MAC $EVENT
