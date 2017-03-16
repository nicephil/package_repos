#!/bin/sh
ath=$1
mac=$2
event=$3
dbfile="/tmp/stationinfo.db"
tablename="STAINFO"

#CREATE TABLE STAINFO(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN);
if [ -f "$dbfile" ]
then
    echo sqlite3  $dbfile "BEGIN TRASACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN);COMMIT;"
fi

case "$event" in
    "AP-STA-CONNECTED")
    
        chan_rssi_assoctime=`wlanconfig $ath list sta | awk '$1 ~ /'${mac}'/{print $3"'\'','\''"$6"'\'','\''"$17}'`
        
        bssid=`ifconfig $ath | awk '$1 ~ /ath/{print $5}'`
        ip=`awk '{if ($4 == "'$mac'") print $1}' /proc/net/arp`
        
        . /lib/functions.sh
        st="ServiceTemplate""${ath:4}"
        config_load wlan_service_template
        config_get _auth $st authentication
        config_get _ps $st portal_scheme
        config_get _ssid $st ssid
        config_load wireless
        config_get _vlan $ath network

        CMD="INSERT INTO ${tablename} VALUES('$mac','$ath','$chan_rssi_assoctime','${ath:3:1}','$bssid','$ip','$_auth','$_ps','$_ssid','${_vlan:3}')"
    ;;

    "AP-STA-DISCONNECTED")
        CMD="DELETE FROM ${tablename} WHERE MAC = $mac"
    ;;
    
esac

echo sqlit3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"

