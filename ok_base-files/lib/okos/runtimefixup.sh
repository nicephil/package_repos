#!/bin/sh

# check if services is restarting
if [ -f "/tmp/restartservices.lock" ]
then
    return 1
fi

if [ -f "/tmp/runtimefixup.lock" ]
then
    return 1
fi


runtimefixup_debug_log () {
    echo "$@" | logger -p 7 -t runtimefixup
}

runtimefixup_err_log () {
    echo "$@" | logger -p 3 -t runtimefixup
}

runtimefixup_trap () {
    runtimefixup_err_log "gets trap on runtimefixup"
    rm -rf /tmp/runtimefixup.lock
}

trap 'runtimefixup_trap; exit 1' INT TERM ABRT QUIT ALRM


touch /tmp/runtimefixup.lock

all_db=$(sqlite3 /tmp/stationinfo.db 'select * from stainfo';sqlite3 /tmp/statsinfo.db 'select * from statsinfo' | awk -F'|' '!a[$1]++')

# delete client who already gone
for client_tmp in $all_db
do
    OIFS=$IFS;IFS='|';set -- $client_tmp;_mac=$1;_ath=$2;IFS=$OIFS        
    __ath=$(apstats -s -m $_mac 2>/dev/null | awk '/'"$_mac"'/{print substr($7,1, length($7)-1);exit}')
    # no find mac really
    if [ -z "$__ath" ]
    then
        runtimefixup_err_log "missed xxclient:$_mac xx_ath:$_ath disconnected event"
        /lib/okos/wifievent.sh $_ath AP-STA-DISCONNECTED $_mac ""
		continue
    fi
done

# active missed client
for client in $(for ath in `iwconfig 2>/dev/null | awk '/ath/{print $1}'`;do wlanconfig $ath list sta; done | awk '$1 !~ /ADDR/{if (!(a[$1]++)) print $1}')
do
    (
    unset _mac
    unset _ath
    client_tmp=$(sqlite3 /tmp/stationinfo.db "SELECT * FROM STAINFO WHERE MAC = \"$client\"")
    [ -n "$client_tmp" ] && {
        OIFS=$IFS;IFS='|';set -- $client_tmp;_mac=$1;_ath=$2;IFS=$OIFS        
    }

    __ath=$(apstats -s -m $client 2>/dev/null | awk '/'"$client"'/{print substr($7,1, length($7)-1);exit}')
    # no find mac really
    if [ -z "$__ath" ]
    then
        # no in db, disconnected quickly
        if [ -z "$_ath" ]
        then
            runtimefixup_err_log "client:$client disconnected quickly"
            continue
        # in db, but disconnected, send disconn event to clear
        else
            runtimefixup_err_log "missed client:$client _ath:$_ath disconnected event"
            /lib/okos/wifievent.sh $_ath AP-STA-DISCONNECTED $client ""
            continue
        fi
    # real mac here
    else
        # no in db, kickmac again
        if [ -z "$_ath" ]
        then
            runtimefixup_err_log "missed __ath:$__ath client:$client connected event"
            iwpriv $__ath kickmac $client
            continue
        # in db, but different ath
        elif [ "$__ath" != "$_ath" ]
        then
            runtimefixup_err_log "missed __ath:$__ath client:$client connected event"
            iwpriv $__ath kickmac $client
            continue
        fi
    fi
    )&
done
wait
rm -rf /tmp/runtimefixup.lock

