#!/bin/sh

DEBUG=

trafstats_trap () {
    logger -t trafstats "gets trap on trafstats" -p 3
    lock -u /tmp/.iptables.lock
}

trap 'trafstats_trap; exit 1' INT TERM ABRT QUIT ALRM


# DEBUG
# $1 - string
trafstats_debug_log ()
{
    [ -n "$DBUG" ] && {
        echo "$@"
        return 0
    }

    echo "$@"  | logger -p 7 -t 'trafstats'
}

trafstats_err_log () {
    [ -n "$DBUG" ] && {
        echo "$@"
        return 0
    }
    echo "$@" | logger -p 3 -t 'trafstats'
}

# $1 - client mac
# $2 - ip var
# ret - 0 - success, 1 - failure
get_ip ()
{
    local mac="$1"
    local ip_var="$2"
    local sta_db="/tmp/stationinfo.db"
    local sta_table="STAINFO"
    
    local rc
    local ip
    
    ip=`sqlite3 $sta_db "select IPADDR from '${sta_table}' where MAC='${mac}' COLLATE NOCASE;"`
    [ -z "$ip" ] && return 1
    
    unset"${ip_var}"
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

    trafstats_debug_log "1-->add_client_track: $mac $_ip"

    [ -z "$mac" -o -z "$_ip" ] && return 1


    # delete first
    del_client_track "$mac"

    trafstats_debug_log "2-->add_client_track: $mac $_ip"
    # add new rule
    lock /tmp/.iptables.lock

    iptables -A client_total_uplink_traf -s "$_ip" -j total_uplink_traf -m comment --comment "$mac"
    iptables -A client_total_downlink_traf -d "$_ip" -j total_downlink_traf -m comment --comment "$mac"
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

    trafstats_debug_log "-->del_client_track: $mac"

    [ -z "$mac" ] && return 1


    lock /tmp/.iptables.lock
    # delete the mac existing in total uplink chain
    local num=$(iptables -L client_total_uplink_traf -n -v --line-number -x 2>&1 | awk '/'"$mac"'/{print $1;exit}' 2>&1)
    if [ -n "$num" ]
    then
        trafstats_debug_log "aa1-->$mac, $num<--"
        iptables -D client_total_uplink_traf "$num"
    fi

    # delete the mac existing in total downlink chain
    local num=$(iptables -L client_total_downlink_traf -n -v --line-number -x 2>&1 | awk '/'"$mac"'/{print $1;exit}' 2>&1)
    if [ -n "$num" ]
    then
        trafstats_debug_log "bb1-->$mac, $num<--"
        iptables -D client_total_downlink_traf "$num"
    fi

    # delete the mac existing in uplink chain
    local num=$(iptables -L client_wan_uplink_traf -n -v --line-number -x 2>&1 | awk '/'"$mac"'/{print $1;exit}' 2>&1)
    if [ -n "$num" ]
    then
        trafstats_debug_log "aa-->$mac, $num<--"
        iptables -D client_wan_uplink_traf "$num"
    fi

    # delete the mac existing in downlink chain
    local num=$(iptables -L client_wan_downlink_traf -n -v --line-number -x 2>&1 | awk '/'"$mac"'/{print $1;exit}' 2>&1)
    if [ -n "$num" ]
    then
        trafstats_debug_log "bb-->$mac, $num<--"
        iptables -D client_wan_downlink_traf "$num"
    fi

    lock -u /tmp/.iptables.lock

    return 0
}

# $1 - client mac
# $2 - uplink var
# $3 - downlink var
# $4 - total uplink var
# $5 - total downlink var
# ret - 0 - success, 1 - failure
fetch_client_stats ()
{
    local mac="$1"
    local uplink_var="$2"
    local downlink_var="$3"
    local total_uplink_var="$4"
    local total_downlink_var="$5"

    unset "${uplink_var}"
    unset "${downlink_var}"
    unset "${total_uplink_var}"
    unset "${total_downlink_var}"

    lock /tmp/.iptables.lock

    local _uplink=$(iptables -L client_wan_uplink_traf -n -v --line-number -x | awk '/'"${mac}"'/{print $3}')
    local _downlink=$(iptables -L client_wan_downlink_traf -n -v --line-number -x | awk '/'"${mac}"'/{print $3}')
    local _total_uplink=$(iptables -L client_total_uplink_traf -n -v --line-number -x | awk '/'"${mac}"'/{print $3}')
    local _total_downlink=$(iptables -L client_total_downlink_traf -n -v --line-number -x | awk '/'"${mac}"'/{print $3}')

    export "${uplink_var}=$_uplink"
    export "${downlink_var}=$_downlink"
    export "${total_uplink_var}=$_total_uplink"
    export "${total_downlink_var}=$_total_downlink"

    lock -u /tmp/.iptables.lock

    return 0
}

