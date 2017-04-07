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

_assoctime_rssi=`wlanconfig $ath list sta | awk '/'"$mac"'/{print $17"|"$6;exit}'`
_assoctime=${_assoctime_rssi%%|*}
_rssi=${_assoctime_rssi##*|}

echo -e "\toption assoctime $_assoctime"
echo -e "\toption ipaddr $_ip"
echo -e "\toption rssi $_rssi"

#CREATE TABLE STAINFO(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER);
sqlite3 /tmp/stationinfo.db "BEGIN TRANSACTION;UPDATE STAINFO set ASSOCTIME=\"$_assoctime\", IPADDR=\"$_ip\", RSSI=\"$_rssi\" WHERE MAC=\"$mac\";COMMIT;" &
