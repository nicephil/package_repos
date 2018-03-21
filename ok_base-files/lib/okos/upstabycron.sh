#!/bin/sh

if [ -f "/tmp/upstabycron.lock" ]
then
    return 0
fi

upstabycron_trap () {
    logger -t upstabycron "gets trap on upstabycron"
    rm -rf /tmp/upstabycron.lock
}

trap 'upstabycron_trap; exit' INT TERM ABRT QUIT ALRM


touch /tmp/upstabycron.lock

# delete client who already gone
for client_tmp in $(sqlite3 /tmp/stationinfo.db 'select * from stainfo')
do
    echo "$client_tmp"
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

# active missed client
for client in $(for ath in `iwconfig 2>/dev/null | awk '/ath/{print $1}'`;do wlanconfig $ath list sta; done | awk '$1 !~ /ADDR/{if (!(a[$1]++)) print $1}')
do
    unset _mac
    unset _ath
    client_tmp=$(sqlite3 /tmp/stationinfo.db "SELECT * FROM STAINFO WHERE MAC = \"$client\"")
    [ -n "$client_tmp" ] && {
        OIFS=$IFS;IFS='|';set -- $client_tmp;_mac=$1;_ath=$2;IFS=$OIFS        
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
    
done

rm -rf /tmp/upstabycron.lock

