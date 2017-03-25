#!/bin/sh
ath=$1
mac=$2
event=$3
dbfile="/tmp/stationinfo.db"
tablename="STAINFO"
CMD=

# ath50 is for debug, so ignore it
if [ "$ath" = "ath50" ]
then
    exit 0
fi

#CREATE TABLE STAINFO(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER);
if [ ! -f "$dbfile" ]
then
    #echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_HMODE,PORTAL_USER);COMMIT;" | logger
    sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER);COMMIT;"
fi

case "$event" in
    "AP-STA-CONNECTED")
    
        chan_rssi_assoctime=`wlanconfig $ath list sta | awk '$1 ~ /'${mac}'/{print $3"'\'','\''"$6"'\'','\''"$17;exit}'`
        
        bssid=`ifconfig $ath | awk '$1 ~ /ath/{print $5;exit}'`
        ip=`awk '{if ($4 == "'$mac'") {print $1; exit}}' /proc/net/arp`
        
        . /lib/functions.sh
        st="ServiceTemplate""${ath:4}"
        config_load wlan_service_template
        config_get _auth $st authentication
        config_get _ps $st portal_scheme
        config_get _ssid $st ssid
        config_load wireless
        config_get _vlan $ath network

        # avoid duplicated record here
        CMD="DELETE FROM ${tablename} WHERE MAC = '$mac'"
        #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
        sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"

        # add new record
        CMD="INSERT INTO ${tablename} VALUES('$mac','$ath','$chan_rssi_assoctime','${ath:3:1}','$bssid','$ip','$_auth','$_ps','$_ssid','${_vlan:3}','','')"
        #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
        sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"
    ;;

    "AP-STA-DISCONNECTED")
        # delete record
        CMD="DELETE FROM ${tablename} WHERE MAC = '$mac'"
        #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
        sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"
    ;;
    
esac

