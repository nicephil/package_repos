#!/bin/sh
ath=$1
mac=$2
event=$3
dbfile="/tmp/stationinfo.db"
tablename="STAINFO"
CMD=

# ath50/ath60 is for debug, so ignore it
if [ "$ath" = "ath50" || "$ath" = "ath60" ]
then
    exit 0
fi

#echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_HMODE,PORTAL_USER,HOSTNAME);COMMIT;" | logger
sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(MAC TEXT PRIMARY KEY NOT NULL,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,HOSTNAME);COMMIT;"

# the dbfile should be delete after wifi down/up
if [ "$ath" = "/lib/wifi" ]
then
    CMD="DELETE FROM '$tablename'"
    #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
    sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"
    return 0
fi

case "$event" in
    "AP-STA-CONNECTED")
        
        # add new record
        CMD="INSERT OR REPLACE INTO ${tablename} (MAC,IFNAME,RADIOID) VALUES('$mac','$ath','${ath:3:1}')"
        #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
        sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"

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
        CMD="UPDATE ${tablename} SET BSSID = '$bssid', AUTHENTICATION = '$_auth', PORTAL_SCHEME = '$_ps', SSID = '$_ssid', VLAN = '${_vlan:3}' WHERE MAC = '$mac'"
        #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
        sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"
    ;;

    "AP-STA-DISCONNECTED")
        # delete record
        CMD="DELETE FROM ${tablename} WHERE MAC = '$mac'"
        #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
        sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"
    ;;

    *)
    ;;
    
esac
