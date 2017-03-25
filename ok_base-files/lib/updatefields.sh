#!/bin/sh

mac="$1"
ath="$2"
ssid="$3"
vlan="br-lan$4"
ip="$5"

portalinfo=`wdctl query "$mac" "$ssid"`

_portal_mode=`echo $portalinfo | awk '/'"$mac"'/{if(NR>1){print $3;exit}}'|tr -d '[]'`
_portal_user=`echo $portalinfo | awk '/'"$mac"'/{if(NR>1){print $5;exit}}'|tr -d '[]'`

if [ -z $ip ]
then
    _ip=`awk '{if ($4 == "'$mac'" && $6 == "'$vlan'") {print $1; exit}}' /proc/net/arp`
else
    _ip=$ip
fi

_assoctime=`wlanconfig $ath list sta | awk '/'"$mac"'/{print $17;exit}'`

echo -e "\toption assoctime $_assoctime"
echo -e "\toption ipaddr $_ip"
echo -e "\toption portal_mode $_portal_mode"
echo -e "\topton portal_user $_portal_user"
