#!/bin/sh

mac=$1
tx_rate_limit=$2
rx_rate_limit=$3
tx_rate_limit_local=$4
rx_rate_limit_local=$5
ath=$6
action=$7

[ -z "$ath" ] && {
ath=`apstats -s -m $mac|awk '/VAP/{print $7}'`
ath="${ath:0:5}"
}

     
logger -t clientevent -p 3 "++setratelimit:mac:$mac, tx_rate_limit:$tx_rate_limit, rx_rate_limit:$rx_rate_limit, tx_rate_limit_local:$tx_rate_limit_local, rx_rate_limit_local:$rx_rate_limit_local, ath:$ath, action:$action"

[ ! "$ath" =~ "ath" ] && { logger -t clientevent "++setratelimit:ath:$ath"; return 1 }

[ -z "$action" ] && action="1"

[ "$action" = "0" ] && {
    /lib/okos/qos.sh del $mac 2>&1 | logger -t clientevent
    logger -t clientevent -p 3 "==/lib/okos/qos.sh del $mac"
}

[ "$action" = "1" ] && {

    # 1. get the ssid QoS weight
    st_name="ServiceTemplate${ath:4}"
    . /lib/functions.sh
    config_load wlan_service_template
    config_get qos_weight ${st_name} bandwidth_priority

    # 2. set the right limit
    /lib/okos/qos.sh add $mac $qos_weight ${tx_rate_limit} ${rx_rate_limit} ${tx_rate_limit_local} ${rx_rate_limit_local} $ath 2>&1 | logger -t clientevent
    logger -t clientevent -p 3 "==/lib/okos/qos.sh add $mac $qos_weight ${tx_rate_limit} ${rx_rate_limit} ${tx_rate_limit_local} ${rx_rate_limit_local} $ath"
}

