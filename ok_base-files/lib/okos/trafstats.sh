#!/bin/sh

DEBUG=

# DEBUG
# $1 - string
trafstats_log ()
{
    [ -n "$DBUG" ] && {
        echo "$1"
        return 0
    }

    echo "$1"  | logger -t 'trafstats'
}

# $1 - client mac
# $2 - ip var
# $3 - ifname
# $4 - ifname var
# ret - 0 - success, 1 - failure
get_ip ()
{
    local mac="$1"
    local ip_var="$2"
    local ifname="$3"
    local sta_db="/tmp/stationinfo.db"
    local arp_db="/tmp/arptables.db"
    
    local rc
    local vlan
    local ip
    if [ -z "$ifname" ]; then
        rc=`sqlite3 $sta_db "select IFNAME,VLAN from STAINFO where MAC='${mac}' COLLATE NOCASE;"`
        OIFS=$IFS;IFS='|';set -- $rc;ifname=$1;vlan=$2;IFS=$OIFS
        vlan="br-lan${vlan}"
        
        [ -z "$ifname" ] && return 1
        [ -z "$vlan" ] && return 1
    else
        if [ ! -z "$debug" ]; then
            rc="'lan3000'" 
        else
            rc=`uci -q show wireless.${ifname}.network`
        fi  
        [ -z "$rc" ] && return 1
        vlan=`echo $rc | awk -F "'" '{print $2}'`
        vlan="br-${vlan}"
    fi  
    
    ip=`sqlite3 $arp_db "select IP from '${vlan}' where MAC='${mac}' COLLATE NOCASE;"`
    [ -z "$ip" ] && return 1
    
    export "${ip_var}=${ip}"
    return 0
} 


# $1 - client mac
# $2 - client ip
# ret - 0 - success, 1 - failure
add_client_track ()
{
    local mac="$1"
    local _ip="$2"

    [ -z "$_ip" ] && get_ip "$mac" _ip

    trafstats_log "1-->add_client_track: $mac $_ip"

    [ -z "$mac" -o -z "$_ip" ] && return 1


    # delete first
    del_client_track "$1"

    # add new rule
    lock /tmp/.iptables.lock

    iptables -A client_wan_uplink_traf -s "$_ip" -m comment --comment "$mac"
    iptables -A client_wan_downlink_traf -d "$_ip" -m comment --comment "$mac"

    lock -u /tmp/.iptables.lock

    return 0
}


# $1 - client mac
# ret - 0 - succes, 1 - failure
del_client_track ()
{
    local mac="$1"

    trafstats_log "1-->del_client_track: $mac"

    [ -z "$mac" ] && return 1


    lock /tmp/.iptables.lock

    # delete the mac existing in uplink chain
    local num=$(iptables -L client_wan_uplink_traf -n -v --line-number -x 2>&1 | awk '/'"$mac"'/{print $1;exit}' 2>&1)
    while [ -n "$num" ]
    do
        trafstats_log "aa-->$num<--"
        iptables -D client_wan_uplink_traf "$num"
        num=$(iptables -L client_wan_uplink_traf -n -v --line-number -x 2>&1 | awk '/'"$mac"'/{print $1;exit}' 2>&1)
    done


    # delete the mac existing in downlink chain
    local num=$(iptables -L client_wan_downlink_traf -n -v --line-number -x 2>&1 | awk '/'"$mac"'/{print $1;exit}' 2>&1)
    while [ -n "$num" ]
    do
        trafstats_log "bb-->$num<--"
        iptables -D client_wan_downlink_traf "$num"
        num=$(iptables -L client_wan_downlink_traf -n -v --line-number -x 2>&1 | awk '/'"$mac"'/{print $1;exit}' 2>&1)
    done

    lock -u /tmp/.iptables.lock

    return 0
}

# $1 - client mac
# $2 - uplink var
# $3 - downlink var
# ret - 0 - success, 1 - failure
fetch_client_stats ()
{
    local mac="$1"
    local uplink_var="$2"
    local downlink_var="$3"

    unset "${uplink_var}"
    unset "${downlink_var}"

    lock /tmp/.iptables.lock

    local _uplink=$(iptables -L client_wan_uplink_traf -n -v --line-number -x | awk '/'"${mac}"'/{print $3}')
    local _downlink=$(iptables -L client_wan_downlink_traf -n -v --line-number -x | awk '/'"${mac}"'/{print $3}')

    export "${uplink_var}=$_uplink"
    export "${downlink_var}=$_downlink"

    lock -u /tmp/.iptables.lock

    return 0
}

