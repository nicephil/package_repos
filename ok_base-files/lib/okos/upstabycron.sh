#!/bin/sh

# check if services is restarting
if [ -f "/tmp/restartservices.lock" ]
then
    return 1
fi

if [ -f "/tmp/upstabycron.lock" ]
then
    return 1
fi

. /lib/okos/trafstats.sh

upsta_debug_log () {
    echo "$@" | logger -p 7 -t upstabycron
}

upsta_err_log () {
    echo "$@" | logger -p 4 -t upstabycron
}

upstabycron_trap () {
    upsta_err_log "gets trap on upstabycron"
    lock -u /tmp/.iptables.lock
    rm -rf /tmp/upstabycron.lock
}

trap 'upstabycron_trap; exit 1' INT TERM ABRT QUIT ALRM


touch /tmp/upstabycron.lock

dbfile="/tmp/statsinfo.db"
tablename="STATSINFO"

#echo sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR,MINRSSI,MAXRSSI,PORTAL_STATUS);COMMIT;" | logger
sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(MAC TEXT PRIMARY KEY NOT NULL,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR,MINRSSI,MAXRSSI,PORTAL_STATUS);COMMIT;"



. /lib/functions/network.sh

# active missed client
for client in $(sqlite3 /tmp/stationinfo.db "SELECT * FROM STAINFO" 2>/dev/null)
do
    OIFS=$IFS;IFS='|';set -- $client;_mac=$1;_ath=$2;_radioid=$6;_bssid=$7;_ip=$8;_auth=$9;_ps=$10;_ssid=$11;_vlan=$12;_pm=$13;_pu=$14;_hostname=$15;_portal_status=$18;IFS=$OIFS        
    _hostname=${_hostname%%.*}

    _gwaddr=""
    network_get_gateway_any _gwaddr "lan${_vlan}"
    [ -z "$_gwaddr" ] && _gwaddr="255.255.255.255"

    vlan_if="br-lan${_vlan}"

    [ -z "$_ip" ] && {
        _ip=`awk '{if ($4 == "'$_mac'" && $6 == "'$vlan_if'") {print $1; exit}}' /proc/net/arp` 
    }
    
    _chan_rssi_assoctime=`wlanconfig $_ath list sta 2>/dev/null | awk '$1 ~ /'${_mac}'/{print $3,$4,$5,$6,$7,$8,$17,$19,$20,$21;exit}'`
    [ -z "$_chan_rssi_assoctime" ] && {
        upsta_err_log "missed _mac:$_mac _ath:$_ath _chan_rssi_assoctime"
        continue
    }
    set -- $_chan_rssi_assoctime;_chan=$1;_ntxrt=$2;_nrxrt=$3;_rssi=$4;_min_rssi=$5;_max_rssi=$6;_assoctime=$7;_smode_sbw=$8;_smode_sbw1=$9;_psmode=$10
    _ntxrt=${_ntxrt%[a-zA-Z]*}
    _nrxrt=${_nrxrt%[a-zA-Z]*}

    if [ -z "$_psmode" ]
    then
        OIFS=$IFS;IFS='_';set -- $_smode_sbw;_smode=$3;_sbw=$4;IFS=$OIFS
        _psmode=$_smode_sbw1
    else
        OIFS=$IFS;IFS='_';set -- $_smode_sbw1;_smode=$3;_sbw=$4;IFS=$OIFS
    fi
    _smode=`echo $_smode|tr [A-Z] [a-z]`
    
    # all traffic
    _stats=`apstats -s -i $_ath -m $_mac 2>/dev/null | awk -F'=' '/Tx Data Bytes|Rx Data Bytes|Average Tx Rate|Average Rx Rate|Tx failures|Rx errors/{print $2}'`
    [ -z "$_stats" ] && {
        upsta_err_log "missed _mac:$_mac _ath:$_ath apstats -s"
        continue
    }
    set -- $_stats;_txB=$1;_rxB=$2;_atxrb=$3;_arxrb=$4;_txfs=$5;_rxes=$6
    _ts=`date +%s`
    _wan_txB=""
    _wan_rxB=""
    _txB=""
    _rxB=""
    fetch_client_stats $_mac _wan_txB _wan_rxB _txB _rxB
    # echo "_mac:$_mac,_txB:$_txB,_rxB:$_rxB,_wan_txB:$_wan_txB,_wan_rxB:$_wan_rxB" | logger -t getstainfo
    [ -z "$_wan_txB" ] && _wan_txB="0"
    [ -z "$_wan_rxB" ] && _wan_rxB="0"
    [ -z "$_txB" ] && _txB="0"
    [ -z "$_rxB" ] && _rxB="0"
   
    # add new record
    #echo sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR,MINRSSI,MAXRSSI,PORTAL_STATUS);COMMIT;" | logger
    CMD="INSERT OR REPLACE INTO ${tablename} VALUES('$_mac','$_ath','$_chan','$_rssi','$_assoctime','${_ath:3:1}','$_bssid','$_ip','$_auth','$_ps','$_ssid','$_vlan','$_pm','$_pu','$_smode','$_sbw','$_ntxrt','$_nrxrt','$_txB','$_rxB','$_atxrb','$_arxrb','$_txfs','$_rxes','$_ts','$_hostname','$_psmode','$_wan_txB','$_wan_rxB','$_gwaddr','$_min_rssi', '$_max_rssi', '$_portal_status')"
    #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
    sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"
   
done

rm -rf /tmp/upstabycron.lock

