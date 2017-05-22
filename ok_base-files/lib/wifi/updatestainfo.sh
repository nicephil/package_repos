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

# the dbfile should be delete after wifi down/up
if [ "$ath" = "/lib/wifi" ]
then
    rm -rf $dbfile
fi

#echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_HMODE,PORTAL_USER);COMMIT;" | logger
sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(MAC TEXT PRIMARY KEY NOT NULL,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER);COMMIT;"

case "$event" in
    "AP-STA-CONNECTED")
        
        bssid=`ifconfig $ath | awk '$1 ~ /ath/{print $5;exit}'`
        
        . /lib/functions.sh
        st="ServiceTemplate""${ath:4}"
        config_load wlan_service_template
        config_get _auth $st authentication
        config_get _ps $st portal_scheme
        config_get _ssid $st ssid
        config_load wireless
        config_get _vlan $ath network

        # add new record
        CMD="INSERT OR REPLACE INTO ${tablename} VALUES('$mac','$ath','','','','${ath:3:1}','$bssid','','$_auth','$_ps','$_ssid','${_vlan:3}','','')"
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

