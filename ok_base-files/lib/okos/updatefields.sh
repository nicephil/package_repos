#!/bin/sh

mac="$1"
ath="$2"
ssid="$3"
vlan="br-lan$4"
_ip="$5"

if [ -z $_ip ]
then
    _ip=`awk '{if ($4 == "'$mac'" && $6 == "'$vlan'") {print $1; exit}}' /proc/net/arp`
fi

_chan_rssi_assoctime=`wlanconfig $ath list sta | awk '$1 ~ /'${mac}'/{print $3"'\'','\''"$6"'\'','\''"$17;exit}'`
OIFS=$IFS;IFS='|';set -- $_chan_rssi_assoctime;_chan=$1;_rssi=$2;_assoctime=$3;IFS=$OIFS

echo -e "\toption channel $_chan"
echo -e "\toption assoctime $_assoctime"
echo -e "\toption ipaddr $_ip"
echo -e "\toption rssi $_rssi"

#CREATE TABLE STAINFO(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER);
sqlite3 /tmp/stationinfo.db "BEGIN TRANSACTION;UPDATE STAINFO set CHAN=\"$_chan\", ASSOCTIME=\"$_assoctime\", IPADDR=\"$_ip\", RSSI=\"$_rssi\" WHERE MAC=\"$mac\";COMMIT;" &
