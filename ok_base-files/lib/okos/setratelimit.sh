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
    st_name="ServiceTemplate${ath:4}"
    . /lib/functions.sh
    config_load wlan_service_template
    config_get qos_weight ${st_name} bandwidth_priority

    # 2. set the right limit
    /lib/okos/qos.sh add $mac $qos_weight ${tx_rate_limit} ${rx_rate_limit} $ath
}



