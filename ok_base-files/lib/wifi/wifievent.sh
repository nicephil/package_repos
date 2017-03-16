#!/bin/sh

IFNAME=$1
EVENT=$2
CLIENT_MAC=$3

logger "=======> $*" 

/lib/wifi/updatestainfo.sh $IFNAME $CLIENT_MAC $EVENT
