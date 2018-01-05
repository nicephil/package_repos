#!/bin/sh

if [ -f "/tmp/getstainfo.lock" ]
then
    exit 0
fi


trap 'getstainfo_trap; exit' INT TERM ABRT QUIT ALRM

getstainfo_trap () {
    logger -t getstainfo "gets trap"
    rm -rf /tmp/getstainfo.lock
}


touch /tmp/getstainfo.lock

dbfile="/tmp/statsinfo.db"
tablename="STATSINFO"

. /lib/okos/trafstats.sh
. /lib/functions/network.sh


rm -rf $dbfile; touch $dbfile
#echo sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR);COMMIT;" | logger
sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(MAC TEXT PRIMARY KEY NOT NULL,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR);COMMIT;"

#echo sqlite3 /tmp/stationinfo.db "BEGIN TRANSACTION;CREATE TABLE STAINFO(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_HMODE,PORTAL_USER,HOSTNAME);COMMIT;" | logger
for client in $(for ath in `iwconfig 2>/dev/null | awk '/ath/{print $1}'`;do wlanconfig $ath list sta; done | awk '$1 !~ /ADDR/{if (!(a[$1]++)) print $1}')
do
    client_tmp=$(sqlite3 /tmp/stationinfo.db "SELECT * FROM STAINFO WHERE MAC = \"$client\"")
    [ -n "$client_tmp" ] && {
        OIFS=$IFS;IFS='|';set -- $client_tmp;_mac=$1;_ath=$2;_radioid=$6;_bssid=$7;_ip=$8;_auth=$9;_ps=$10;_ssid=$11;_vlan=$12;_pm=$13;_pu=$14;_hostname=$15;IFS=$OIFS        
        _hostname=${_hostname%%.*}
    }
    [ -z "$client_tmp" ] && {
        for _ath in `iwconfig 2>/dev/null | awk '/ath/{print $1}'`
        do
            tmp_str=`wlanconfig $_ath list sta | awk -n "/$client/p"`
            [ -n "$tmp_str" ] && break
        done
        [ -z "$tmp_str" ] && continue

        _bssid=`ifconfig $_ath | awk '$1 ~ /ath/{print $5;exit}'`
        
        . /lib/functions.sh
        st="ServiceTemplate""${ath:4}"
        config_load wlan_service_template
        config_get _auth $st authentication
        config_get _ps $st portal_scheme
        config_get _ssid $st ssid
        config_load wireless
        config_get _vlan $ath network
        _mac=$client
        _radioid=${_ath:3:1}
        _pm=""
        _pu=""
    }
    _gwaddr=""
    network_get_gateway_any _gwaddr "lan${_vlan}"
    [ -z "$_gwaddr" ] && _gwaddr="255.255.255.255"

    vlan_if="br-lan${_vlan}"

    [ -z "$_ip" ] && {
        _ip=`awk '{if ($4 == "'$_mac'" && $6 == "'$vlan_if'") {print $1; exit}}' /proc/net/arp` 
    }
    
    _chan_rssi_assoctime=`wlanconfig $_ath list sta | awk '$1 ~ /'${_mac}'/{print $3,$4,$5,$6,$17,$19,$20,$21;exit}'`
    [ -z $_chan_rssi_assoctime ] && continue
    set -- $_chan_rssi_assoctime;_chan=$1;_ntxrt=$2;_nrxrt=$3;_rssi=$4;_assoctime=$5;_smode_sbw=$6;_smode_sbw1=$7;_psmode=$8
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
    _stats=`apstats -s -i $_ath -m $_mac | awk -F'=' '/Tx Data Bytes|Rx Data Bytes|Average Tx Rate|Average Rx Rate|Tx failures|Rx errors/{print $2}'`
    [ -z "$_stats" ] && continue
    set -- $_stats;_txB=$1;_rxB=$2;_atxrb=$3;_arxrb=$4;_txfs=$5;_rxes=$6
    _ts=`date +%s`
    _wan_txB=""
    _wan_rxB=""
    fetch_client_stats $_mac _wan_txB _wan_rxB
    # echo "_wan_txB:$_wan_txB, _wan_rxB:$_wan_rxB" | logger -t getstainfo
    [ -z "$_wan_txB" ] && _wan_txB="0"
    [ -z "$_wan_rxB" ] && _wan_rxB="0"
   
    # add new record
    #echo sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR);COMMIT;" | logger
    CMD="INSERT INTO ${tablename} VALUES('$_mac','$_ath','$_chan','$_rssi','$_assoctime','${_ath:3:1}','$_bssid','$_ip','$_auth','$_ps','$_ssid','$_vlan','$_pm','$_pu','$_smode','$_sbw','$_ntxrt','$_nrxrt','$_txB','$_rxB','$_atxrb','$_arxrb','$_txfs','$_rxes','$_ts','$_hostname','$_psmode','$_wan_txB','$_wan_rxB','$_gwaddr')"
    #echo sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;" | logger
    sqlite3 $dbfile "BEGIN TRANSACTION;${CMD};COMMIT;"
done

rm -rf /tmp/getstainfo.lock

