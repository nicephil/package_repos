#!/bin/sh

if [ -f "/tmp/restartservices.lock" ]
then
    return 1
fi

if [ -f "/tmp/upstabycron.lock" ]
then
    return 1
fi

. /lib/okos/trafstats.sh

upstabycron_trap () {
    logger -t upstabycron "gets trap on upstabycron"
    lock -u /tmp/.iptables.lock
    rm -rf /tmp/upstabycron.lock
}

trap 'upstabycron_trap; exit 1' INT TERM ABRT QUIT ALRM


touch /tmp/upstabycron.lock

# delete client who already gone
for client_tmp in $(sqlite3 /tmp/stationinfo.db 'select * from stainfo')
do
    unset _mac
    unset _ath
    OIFS=$IFS;IFS='|';set -- $client_tmp;_mac=$1;_ath=$2;IFS=$OIFS        
    client=$_mac
    __ath=$(apstats -s -m $client | awk '/'"$client"'/{print substr($7,1, length($7)-1);exit}')
    # no find mac really
    if [ -z "$__ath" ]
    then
        echo "missed xxclient:$client xx_ath:$_ath disconnected event" | logger -t clientevent -p 3
        /lib/okos/wifievent.sh $_ath AP-STA-DISCONNECTED $client "" &
    fi
done

dbfile="/tmp/statsinfo.db"
tablename="STATSINFO"

#echo sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR,MINRSSI,MAXRSSI,PORTAL_STATUS);COMMIT;" | logger
sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(MAC TEXT PRIMARY KEY NOT NULL,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR,MINRSSI,MAXRSSI,PORTAL_STATUS);COMMIT;"



. /lib/functions/network.sh

# active missed client
for client in $(for ath in `iwconfig 2>/dev/null | awk '/ath/{print $1}'`;do wlanconfig $ath list sta; done | awk '$1 !~ /ADDR/{if (!(a[$1]++)) print $1}')
do
    unset _mac
    unset _ath
    unset _radioid
    unset _bssid
    unset _ip
    unset _auth
    unset _ps
    unset _ssid
    unset _vlan
    unset _pm
    unset _pu
    unset _hostname
    unset _portal_status
    client_tmp=$(sqlite3 /tmp/stationinfo.db "SELECT * FROM STAINFO WHERE MAC = \"$client\"")
    [ -n "$client_tmp" ] && {
        OIFS=$IFS;IFS='|';set -- $client_tmp;_mac=$1;_ath=$2;_radioid=$6;_bssid=$7;_ip=$8;_auth=$9;_ps=$10;_ssid=$11;_vlan=$12;_pm=$13;_pu=$14;_hostname=$15;_portal_status=$18;IFS=$OIFS        
        _hostname=${_hostname%%.*}
    }

    __ath=$(apstats -s -m $client | awk '/'"$client"'/{print substr($7,1, length($7)-1);exit}')
    # no find mac really
    if [ -z "$__ath" ]
    then
        # no in db, disconnected quickly
        if [ -z "$_ath" ]
        then
            echo "client:$client disconnected quickly" | logger -t clientevent -p 3
            continue
        # in db, but disconnected, send disconn event to clear
        else
            echo "missed client:$client _ath:$_ath disconnected event" | logger -t clientevent -p 3
            /lib/okos/wifievent.sh $_ath AP-STA-DISCONNECTED $client "" &
            continue
        fi
    # real mac here
    else
        # no in db, kickmac again
        if [ -z "$_ath" ]
        then
            echo "missed __ath:$__ath client:$client connected event" | logger -t clientevent -p 3
            iwpriv $__ath kickmac $client
            continue
        # in db, but different ath
        elif [ "$__ath" != "$_ath" ]
        then
            echo "missed __ath:$__ath client:$client connected event" | logger -t clientevent -p 3
            iwpriv $__ath kickmac $client
            continue
        fi
    fi

     _gwaddr=""
    network_get_gateway_any _gwaddr "lan${_vlan}"
    [ -z "$_gwaddr" ] && _gwaddr="255.255.255.255"

    vlan_if="br-lan${_vlan}"

    [ -z "$_ip" ] && {
        _ip=`awk '{if ($4 == "'$_mac'" && $6 == "'$vlan_if'") {print $1; exit}}' /proc/net/arp` 
    }
    
    _chan_rssi_assoctime=`wlanconfig $_ath list sta | awk '$1 ~ /'${_mac}'/{print $3,$4,$5,$6,$7,$8,$17,$19,$20,$21;exit}'`
    [ -z "$_chan_rssi_assoctime" ] && {
        echo "missed _mac:$_mac _ath:$_ath disconnected event" | logger -t clientevent -p 3
        /lib/okos/wifievent.sh $_ath AP-STA-DISCONNECTED $mac ""  &
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
    _stats=`apstats -s -i $_ath -m $_mac | awk -F'=' '/Tx Data Bytes|Rx Data Bytes|Average Tx Rate|Average Rx Rate|Tx failures|Rx errors/{print $2}'`
    [ -z "$_stats" ] && {
        echo "missed _mac:$_mac _ath:$_ath disconnected event" | logger -t clientevent -p 3
        /lib/okos/wifievent.sh $_ath AP-STA-DISCONNECTED $mac "" &
        continue
    }
    set -- $_stats;_txB=$1;_rxB=$2;_atxrb=$3;_arxrb=$4;_txfs=$5;_rxes=$6
    _ts=`date +%s`
    _wan_txB=""
    _wan_rxB=""
    _txB=""
    _rxB=""
    fetch_client_stats $_mac _wan_txB _wan_rxB _txB _rxB
    # echo "_txB:$_txB,_rxB:$_rxB,_wan_txB:$_wan_txB,_wan_rxB:$_wan_rxB" | logger -t getstainfo
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

