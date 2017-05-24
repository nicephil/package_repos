#!/bin/sh

mac=$1
tx_rate_limit=$2
rx_rate_limit=$3
ath=$4
action=$5

[ "$action" = "0" ] && {
    /lib/okos/qos.sh del $mac
}

[ "$action" = "1" ] && {

    # 1. get the ssid QoS weight
    qos_weight=1

    # 2. set the right limit
    /lib/okos/qos.sh add $mac $qos_weight ${tx_rate_limit} ${rx_rate_limit} $ath
}



