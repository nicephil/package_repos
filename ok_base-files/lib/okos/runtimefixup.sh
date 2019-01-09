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

all_db=$(sqlite3 /tmp/stationinfo.db 'select * from stainfo' 2>/dev/null;sqlite3 /tmp/statsinfo.db 'select * from statsinfo' | awk -F'|' '!a[$1]++' 2>/dev/null)
apstats_log=$(apstats -a -R 2>/dev/null)
all_clients=$(for ath in `iwconfig 2>/dev/null | awk '/ath/{print $1}'`;do wlanconfig $ath list sta; done | awk '$1 !~ /ADDR/{if (!(a[$1]++)) print $1}')
all_stationinfo_db=$(sqlite3 /tmp/stationinfo.db "SELECT * FROM STAINFO" 2>/dev/null)
all_iptables_log=$(iptables -S WhiteList 2>/dev/null;iptables -t nat -S GotoPortal 2>/dev/null)


# delete client who already gone
for client_tmp in $all_db
do
    OIFS=$IFS;IFS='|';set -- $client_tmp;_mac=$1;_ath=$2;IFS=$OIFS        
    __ath=$(echo "$apstats_log" | awk '/'"$_mac"'/{print substr($7,1, length($7)-1);exit}')
    # no find mac really
    if [ -z "$__ath" ]
    then
        echo "{'sta_mac':'${_mac}','logmsg':'missed disconnected event on $_ath'}" | logger -p 6 -t "200-STA"
        /lib/okos/wifievent.sh $_ath AP-STA-DISCONNECTED $_mac ""
		continue
    fi
    __iptables_check=`echo "$all_iptables_log" | grep -i $_mac`
    if [ -z "$__iptables_check" ]
    then
        echo "{'sta_mac':'${_mac}','logmsg':'missed proper iptables rules on $__ath'}" | logger -p 6 -t "200-STA"
        /lib/okos/wifievent.sh $__ath AP-STA-CONNECTED $_mac ""
        continue
    fi
done

# active missed client
for client in $all_clients
do
    (
    unset _mac
    unset _ath
    client_tmp=$(echo "$all_stationinfo_db" | awk '/'"$client"'/{print $0;exit}')
    [ -n "$client_tmp" ] && {
        OIFS=$IFS;IFS='|';set -- $client_tmp;_mac=$1;_ath=$2;IFS=$OIFS        
    }
    __ath=$(echo "$apstats_log" | awk '/'"$client"'/{print substr($7,1, length($7)-1);exit}')
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
            echo "{'sta_mac':'${client}','logmsg':'missed disconnected event on $_ath'}" | logger -p 6 -t "200-STA"
            /lib/okos/wifievent.sh $_ath AP-STA-DISCONNECTED $client ""
            continue
        fi
    # real mac here
    else
        # no in db, kickmac again
        if [ -z "$_ath" ]
        then
            echo "{'sta_mac':'${client}','logmsg':'missed disconnected event on $__ath'}" | logger -p 6 -t "200-STA"
            #iwpriv $__ath kickmac $client
            continue
        # in db, but different ath
        elif [ "$__ath" != "$_ath" ]
        then
            echo "{'sta_mac':'${client}','logmsg':'missed disconnected event on $__ath'}" | logger -p 6 -t "200-STA"
            #iwpriv $__ath kickmac $client
            continue
        fi
    fi
    )&
done
wait
rm -rf /tmp/runtimefixup.lock

