#!/bin/sh

IFNAME=$1
EVENT=$2
CLIENT_MAC=$3

logger -t hostapd_cli "=======>$*" 

if [ -f "/tmp/wifievent.pipe" ]
then
    echo "$IFNAME $CLIENT_MAC $EVENT" > /tmp/wifievent.pipe
else
    /lib/okos/clientevent.py
    sleep 1
    echo "$IFNAME $CLIENT_MAC $EVENT" > /tmp/wifievent.pipe
fi


/lib/wifi/updatestainfo.sh $IFNAME $CLIENT_MAC $EVENT
