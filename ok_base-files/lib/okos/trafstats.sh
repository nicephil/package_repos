#!/bin/sh

DEBUG=
ebtables_CMD="ebtables"

. /lib/okos/qos_id.sh

# DEBUG
# $1 - string
trafstats_debug_log ()
{
    [ -n "$DBUG" ] && {
        echo "$@"
        return 0
    }

    echo "$@"  | logger -p 3 -t 'trafstats'
}

trafstats_err_log () {
    [ -n "$DBUG" ] && {
        echo "$@"
        return 0
    }
    echo "$@" | logger -p 3 -t 'trafstats'
}

# $1 - client mac
# $2 - ath
# ret - 0 - success, 1 - failure
add_client_track ()
{
    local mac="$1"
    local ifname="$2"
    local id

    trafstats_debug_log "add_client_track: $mac $ifname"

    [ -z "$mac"  -o -z "$ifname" ] && return 1

    # get mark id and set it for qos
    qos_del_id_by_mac $mac
    id=$(qos_new_id $mac $ifname)
    trafstats_debug_log "Generate ID:${id} for client [${ifname}/${mac}]."

    # add new rule
    local rule=$($ebtables_CMD -L client_total_uplink_traf --Lx --Lmac2 2>&1 | sed -n '/'"$mac"'/s/-A/-D/p' 2>&1)
    if [ -z "$rule" ]
    then
        $ebtables_CMD -A client_total_uplink_traf -s "$mac" -p ipv4 -j mark --mark-or $((id<<16)) --mark-target CONTINUE
        $ebtables_CMD -A client_total_uplink_traf -s "$mac" -p ipv4 -j total_uplink_traf

    fi
    local rule=$($ebtables_CMD -L client_total_downlink_traf --Lx  --Lmac2 2>&1 | sed -n '/'"$mac"'/s/-A/-D/p' 2>&1)
    if [ -z "$rule" ]
    then
        $ebtables_CMD -A client_total_downlink_traf -d "$mac" -p ipv4 -j mark --mark-or $(((id+split_id)<<16)) --mark-target CONTINUE
        $ebtables_CMD -A client_total_downlink_traf -d "$mac" -p ipv4 -j total_downlink_traf
    fi
    local rule=$($ebtables_CMD -L client_wan_uplink_traf --Lx --Lmac2  2>&1 | sed -n '/'"$mac"'/s/-A/-D/p' 2>&1)
    if [ -z "$rule" ]
    then
        $ebtables_CMD -A client_wan_uplink_traf -s "$mac" -p ipv4 -j total_wan_uplink_traf
    fi
    local rule=$($ebtables_CMD -L client_wan_downlink_traf --Lx --Lmac2 2>&1 | sed -n '/'"$mac"'/s/-A/-D/p' 2>&1)
    if [ -z "$rule" ]
    then
        $ebtables_CMD -A client_wan_downlink_traf -d "$mac" -p ipv4 -j total_wan_downlink_traf
    fi

    return 0
}


# $1 - client mac
# ret - 0 - succes, 1 - failure
del_client_track ()
{
    local mac="$1"

    trafstats_debug_log "del_client_track: $mac"

    [ -z "$mac" ] && return 1

    qos_del_id_by_mac $mac

    # delete the mac existing in total uplink chain
    local rules=$($ebtables_CMD -L client_total_uplink_traf --Lx --Lmac2  2>&1 | sed -n '/'"$mac"'/s/-A/-D/p' 2>&1)
    echo "$rules" | while read rule
    do
        if [ -n "$rule" ]
        then
            trafstats_debug_log "$mac, $rule"
            for i in 1 2 3
            do
                $rule
                [ "$?" = "0" ] && break
            done
        fi
    done

    # delete the mac existing in total downlink chain
    local rules=$($ebtables_CMD -L client_total_downlink_traf --Lx --Lmac2 2>&1 | sed -n '/'"$mac"'/s/-A/-D/p' 2>&1)
    echo "$rules" | while read rule
    do
        if [ -n "$rule" ]
        then
            trafstats_debug_log "$mac, $rule"
            for i in 1 2 3
            do
                $rule
                [ "$?" = "0" ] && break
            done
        fi
    done

    # delete the mac existing in uplink chain
    local rule=$($ebtables_CMD -L client_wan_uplink_traf --Lx --Lmac2 2>&1 | sed -n '/'"$mac"'/s/-A/-D/p' 2>&1)
    if [ -n "$rule" ]
    then
        trafstats_debug_log "$mac, $rule"
        for i in 1 2 3
        do
            $rule
            [ "$?" = "0" ] && break
        done
    fi

    # delete the mac existing in downlink chain
    local rule=$($ebtables_CMD -L client_wan_downlink_traf --Lx --Lmac2 2>&1 | sed -n '/'"$mac"'/s/-A/-D/p' 2>&1)
    if [ -n "$rule" ]
    then
        trafstats_debug_log "$mac, $rule"
        for i in 1 2 3
        do
            $rule
            [ "$?" = "0" ] && break
        done
    fi

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

    local _uplink=$($ebtables_CMD -L client_wan_uplink_traf --Lc --Lmac2 | awk '/'"${mac}"'/{print $NF;exit}')
    local _downlink=$($ebtables_CMD -L client_wan_downlink_traf --Lc --Lmac2 | awk '/'"${mac}"'/{print $NF;exit}')
    local _total_uplink=$($ebtables_CMD -L client_total_uplink_traf --Lc --Lmac2 | awk '/'"${mac}"'/{print $NF;exit}')
    local _total_downlink=$($ebtables_CMD -L client_total_downlink_traf --Lc --Lmac2 | awk '/'"${mac}"'/{print $NF;exit}')

    [ -z "$_uplink" ] && _uplink=0
    [ -z "$_downlink" ] && _downlink=0
    [ -z "$_total_uplink" ] && _total_uplink=0
    [ -z "$_total_downlink" ] && _total_downlink=0

    export "${uplink_var}=$_uplink"
    export "${downlink_var}=$_downlink"
    export "${total_uplink_var}=$_total_uplink"
    export "${total_downlink_var}=$_total_downlink"

    return 0
}

