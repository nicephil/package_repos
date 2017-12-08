#!/bin/sh

#. /lib/okos/arp_events.sh

LOG_MERG=0
LOG_NOTICE=4
LOG_WARNING=5
LOG_INFO=6
LOG_DEBUG=7
log ()
{
    local pri=$1
    shift 1
    echo "$@" | logger -t arpwatch_hook -p $pri
}
run ()
{
    local cmd=$1
    log $LOG_DEBUG "$cmd"
    eval "$cmd" 2>&1 | logger -t arpwatch_hook -p $LOG_DEBUG
}

arpwatch_trap ()
{
    log $LOG_DEBUG "Try to unlock arpwatch.lock"
    lock -u /var/run/arpwatch.lock
    log $LOG_DEBUG "Unlock arpwatch.lock successfully."
}

SQL=sqlite3
ARPDB="$SQL /tmp/arptables.db"
STADB="$SQL /tmpstationinfo.db"

get_vap_by_mac ()
{
    local mac=$1
    local vap
    local rc

    #vap=`$STADB "select IFNAME from STAINFO where MAC='${mac}' COLLATE NOCASE;"`

    rc=`apstats -s -m ${mac}`
    [ -z "$rc" ] && log $LOG_DEBUG "Client $mac is not a wireless station." && echo "" && return 1
    vap=`echo $rc | sed 's/.*(under VAP \([a-z0-9]*\)).*/\1/'`
    [ -z "$vap" ] && log $LOG_DEBUG "Cannot parse VAP if for Client $mac ." && echo "" && return 1

    echo "${vap}"
}

call_event ()
{
    local mac=$1

    local ifname=$( get_vap_by_mac $mac )
    log $LOG_DEBUG "Get a wireless Client $mac on VAP $ifname ."

    local event

    if [ ! -z "$ifname" ]; then
        event="${ifname} ${mac} STA-IP-CHANGED"
        log $LOG_DEBUG "Call Event '${event}'"
        echo "$event" > /tmp/wifievent.pipe
    else
        log $LOG_DEBUG "No Station Infor."
    fi
}

new_entry ()
{
    local brname=$1
    local mac=$2
    local ip=$3
    local ts=$4
    local hostname=$5

    log $LOG_INFO "New Entry for mac[${mac} ip[${ip}] hostname[${hostname}] on timestamp[${ts}]"
    
    run "$ARPDB \"INSERT OR REPLACE INTO '${brname}' (MAC, IP, HOSTNAME, TS) VALUES ('${mac}', '${ip}', '${hostname}', '${ts}');\""
    #run "$ARPDB \"SELECT \"*\" FROM '${brname}';\""

    call_event $mac
}

new_activity ()
{
    local brname=$1
    local mac=$2
    local ip=$3
    local ts=$4
    local hostname=$5

    log $LOG_DEBUG "New Activity for mac[${mac}] ip[${ip}] hostname[${hostname}] timestamp[${ts}]"

    if [ -z $hostname ]; then
        hostname=`host $ip`
    fi
    if [ ! -z $hostname ]; then
        :
        #run "$ARPDB \"UPDATE '${brname}' SET HOSTNAME='${hostname}' WHERE MAC='${mac}' COLLATE NOCASE;\""
        #run "$ARPDB \"SELECT \"*\" FROM '${brname}';\""
    fi

    #call_event $mac
}

ip_changed ()
{
    local brname=$1
    local mac=$2
    local oldip=$3
    local ip=$4
    local ts=$5
    local hostname=$6

    log $LOG_DEBUG "IP Changed for mac[${mac}] from [${oldip}] to [${ip}]"
    
    run "$ARPDB \"INSERT OR REPLACE INTO '${brname}' (MAC, IP, HOSTNAME, TS) VALUES ('${mac}', '${ip}', (select HOSTNAME from '${brname}' where MAC='${mac}' COLLATE NOCASE), '${ts}');\""
    if [ ! -z $hostname ]; then
        run "$ARPDB \"UPDATE '${brname}' SET HOSTNAME='${hostname}' WHERE MAC='${mac}' COLLATE NOCASE;\""
    fi
    #run "$ARPDB \"SELECT \"*\" FROM '${brname}';\""

    call_event $mac
}

arpwatch_hook ()
{
    local brname=$1
    local mac=`echo $2 | tr 'A-Z' 'a-z'`
    local ip=$3
    local ts=$4
    local hostname=$5

    local record=`$ARPDB "SELECT * FROM '${brname}' WHERE MAC='${mac}' COLLATE NOCASE;"`
    log $LOG_DEBUG "Record:" $record

    if [ -z $record ]; then
        new_entry $brname $mac $ip $ts $hostname
    else
        OIFS=$IFS;IFS='|';set -- $record;rcmac=$1;rcip=$2;rchostn=$3;rcts=$4;IFS=OIFS
        if [ $ip == $rcip ]; then
            new_activity $brname $mac $ip $ts $hostname
        else
            ip_changed $brname $mac $rcip $ip $ts $hostname
        fi
    fi
}

lock /var/run/arpwatch.lock
trap 'arpwatch_trap; exit' INT TERM ABRT QUIT ALRM


log $LOG_DEBUG "Hullo $@!"
arpwatch_hook $@
log $LOG_DEBUG "ARPWatch Hook Completed!"

lock -u /var/run/arpwatch.lock
