#!/bin/sh

. /lib/okos/qos_id.sh

LOG_MERG=0
LOG_NOTICE=4
LOG_WARNING=5
LOG_INFO=6
LOG_DEBUG=7

qos_log ()
{
    local pri=$1
    shift 1
    echo "$@" | logger -t qosscript -p $pri
}

qos_run ()
{
    local cmd=$1
    echo "==> ${cmd}" | logger -t qosscript -p $LOG_DEBUG
    [ -z "$debug" ] && eval "$cmd"
}

#debug=True
QDISC="htb"

if [ ! -z "$debug" ]; then
    ifaces="ath00 ath10 ath01 ath11 eth0 "
else
    ifaces="`ifconfig | awk '/ath/{print $1}'` eth0 "
fi
[ ! -z "$debug" ] && echo "interfaces: $ifaces "

FULL_SPEED_eth0="500000"


qos_htb_add_classes ()
{
    local iface=$1
    local id=$2
    local wt=$3
    local tx=$4
    local rx=$5
    local lan_tx=$6
    local lan_rx=$7

    # uplink
    local id_tmp=$(printf "%x" ${id})
    local param="parent 1:1 classid 1:$id_tmp htb burst 15k rate $((${wt}*12))kbit ceil"
    for _iface in ${ifaces}
    do
        if [ "$_iface" != "$iface" ]
        then
            qos_run "tc class add dev $_iface $param $lan_tx"
            qos_run "tc qdisc add dev $_iface parent 1:$id_tmp sfq perturb 10"
        fi
    done

    # downlink
    local id_tmp=$(printf "%x" $((id+split_id)))
    local param="parent 1:1 classid 1:${id_tmp} htb burst 15k rate $((${wt}*12))kbit ceil"
    qos_run "tc class add dev $iface $param $lan_rx"
    qos_run "tc qdisc add dev $iface parent 1:$id_tmp sfq perturb 10"
}

qos_add_filters ()
{
    local iface=$1
    local mac=$2
    local id=$3

    # uplink
    local uplink_id_tmp=$(printf "%x" ${id})
    local uplink_fwid_tmp=$(printf "%x" $((id<<16)))
    #qos_run "iptables -t mangle -A TC_USER -m mark --mark 0x${uplink_fwid_tmp}/0xFFFF0000 -j CLASSIFY --set-class 1:${uplink_id_tmp}"
    for _iface in ${ifaces}
    do
        if [ "$_iface" != "$iface" ]
        then
            qos_run "tc filter add dev $_iface protocol ip parent 1:0 prio 1 handle 0x${uplink_fwid_tmp} fw flowid 1:${uplink_id_tmp}"
        fi
    done

    # downlink
    local downlink_id_tmp=$(printf "%x" $((id+split_id)))
    local downlink_fwid_tmp=$(printf "%x" $(((id+split_id)<<16)))
    #qos_run "iptables -t mangle -A TC_USER -m mark --mark 0x${downlink_fwid_tmp}/0xFFFF0000 -j CLASSIFY --set-class 1:${downlink_id_tmp}"
    qos_run "tc filter add dev $iface protocol ip parent 1:0 prio 1 handle 0x${downlink_fwid_tmp} fw flowid 1:${downlink_id_tmp}"
}

qos_add ()
{
    # add aa:bb:cc:dd:ee:ff pri tx_up rx_up lan_tx_up lan_rx_up ifname
    local mac=`echo $1 | tr 'A-Z' 'a-z'`
    local pri=$2
    local tx
    [ ! -z $3 ] && tx=$3 || tx=$FULL_SPEED_eth0
    [ $tx -eq 0 ] && tx=$FULL_SPEED_eth0
    tx="${tx}kbit"
    local rx
    [ ! -z $4 ] && rx=$4 || rx=$FULL_SPEED_eth0
    [ $rx -eq 0 ] && rx=$FULL_SPEED_eth0
    rx="${rx}kbit"
    local lan_tx
    [ ! -z $5 ] && lan_tx=$5 || lan_tx=$FULL_SPEED_eth0
    [ $lan_tx -eq 0 ] && lan_tx=$FULL_SPEED_eth0
    lan_tx="${lan_tx}kbit"
    local lan_rx
    [ ! -z $6 ] && lan_rx=$6 || lan_rx=$FULL_SPEED_eth0
    [ $lan_rx -eq 0 ] && lan_rx=$FULL_SPEED_eth0
    lan_rx="${lan_rx}kbit"
    local ifname=$7

    local id

    qos_log $LOG_INFO "Add client [${mac}] on <${ifname}> with priority $pri and limitation WAN TX/RX [${tx}/${rx}] LAN TX/RX [${lan_tx}/${lan_rx}]."

    qos_log $LOG_DEBUG "Del client by ${mac}."
    qos_del $mac $ifname

    id=$(qos_get_id $mac)
    [ -z "$id" ] && { qos_log $LOG_DEBUG "no valid id for $mac"; return 1;}
    qos_log $LOG_DEBUG "Get ID:${id} for client [${ifname}/${mac}]."
    qos_${QDISC}_add_classes $ifname $id $pri $tx $rx $lan_tx $lan_rx
    qos_add_filters $ifname $mac $id

    qos_log $LOG_INFO "Add client done"
}

del_tc_by_id_ifname ()
{
    local id=$1
    local ifname=$2
    qos_log $LOG_DEBUG "del_tc_by_id_ifname(): ID:$id IFNAME:$ifname "

    qos_log $LOG_DEBUG "Delete filter to class ${id}."
    local uplink_id_tmp=$(printf "%x" ${id})
    local uplink_fwid_tmp=$(printf "%x" $((id<<16)))
    #qos_run "iptables -t mangle -D TC_USER -m mark --mark 0x${downlink_fwid_tmp}/0xFFFF0000  -j CLASSIFY --set-class 1:${downlink_id_tmp}"
    for _iface in ${ifaces}; do
        if [ "$_iface" !=  "$ifname" ]
        then
            qos_run "tc filter del dev $_iface protocol ip parent 1:0 prio 1 handle 0x${uplink_fwid_tmp} fw flowid 1:${uplink_id_tmp}"
        fi
    done
    local downlink_id_tmp=$(printf "%x" $((id+split_id)))
    local downlink_fwid_tmp=$(printf "%x" $(((id+split_id)<<16)))
    #qos_run "iptables -t mangle -D TC_USER -m mark --mark 0x${uplink_fwid_tmp}/0xFFFF0000 -j CLASSIFY --set-class 1:${uplink_id_tmp}"
    qos_run "tc filter del dev $ifname protocol ip parent 1:0 prio 1 handle 0x${downlink_fwid_tmp} fw flowid 1:${downlink_id_tmp}"

    qos_log $LOG_DEBUG "Delete class for client [${id}]."
    for _iface in ${ifaces}; do
        if [ "$_iface" = "$ifname" ]
        then
            # downlink
            qos_run "tc class del dev $_iface classid 1:${downlink_id_tmp}"
        else
            # uplink
            qos_run "tc class del dev $_iface classid 1:${uplink_id_tmp}"
        fi
    done

    qos_log $LOG_DEBUG "del_tc_by_id_ifname(): done."
}

qos_del ()
{
    local mac=`echo $1 | tr 'A-Z' 'a-z'`
    local ifname=$2
    qos_log $LOG_DEBUG "Del: $@ ."

    local id2
    id2=$(qos_get_id $mac)
    del_tc_by_id_ifname $id2 $ifname

    qos_log $LOG_DEBUG "Del(): done."
}

qos_htb_start_iface ()
{
    local _iface_=$1
    local _speed_="${2}bit"
    qos_run "tc qdisc add dev $_iface_ root handle 1: htb default 30 r2q 1"
    qos_run "tc class add dev $_iface_ parent 1:0 classid 1:1 htb rate $_speed_ ceil $_speed_ burst 150k"
    qos_run "tc class add dev $_iface_ parent 1:1 classid 1:30 htb rate 12kbit ceil $_speed_ burst 150k"
    qos_run "tc qdisc add dev $_iface_ parent 1:30 handle 30: sfq perturb 10"
}

qos_gothrough_wifi()
{
    local section="$1"
    local var="$2"

    config_get _type "$section" "type"
    config_get _ssid "$section" "ssid"
    _ifname="ath50"
    [ "${section:3:1}" = "1" ] && _ifname="ath60"
    if [ -n "$_type" -a "$_type" = "2" ]
    then
        wlanconfig "$_ifname" addatfgroup public "$_ssid"
        wlanconfig "$_ifname" configatfgroup public 20
    else
        wlanconfig "$_ifname" addatfgroup private "$_ssid"
        wlanconfig "$_ifname" configatfgroup private 80
    fi
    wlanconfig "$_ifname" commitatf 1
}

qos_atf_init()
{
    has_guest=$(uci show wireless | grep ".type='2'")
    [ -z "$has_guest" ] && return 0

    . /lib/functions.sh
    config_load wireless
    config_foreach qos_gothrough_wifi "wifi-iface"
}

qos_start ()
{
    qos_log $LOG_INFO "Kickoff QoS service now."
    qos_log $LOG_DEBUG "Touch $id_file for restoring client ID infor."
    touch $id_file

    qos_atf_init

    qos_log $LOG_DEBUG "Install $QDISC qdisc and root class."
    local full_speed
    for iface in $ifaces; do
        case "$iface" in
            ath0*)
                full_speed=100m
                ;;
            ath1*)
                full_speed=500m
                ;;
            *)
                full_speed=900m
                ;;
        esac
        qos_${QDISC}_start_iface $iface $full_speed
    done

    qos_log $LOG_INFO "QoS service done."
}


qos_atf_deinit()
{
    wlanconfig "ath50" delatfgroup public > /dev/null 2>&1
    wlanconfig "ath50" delatfgroup private > /dev/null 2>&1
    wlanconfig "ath60" delatfgroup public > /dev/null 2>&1
    wlanconfig "ath60" delatfgroup private > /dev/null 2>&1
}


qos_stop ()
{
    qos_log $LOG_INFO "Stop QoS service now."

    qos_atf_deinit

    qos_log $LOG_INFO "Remove root."
    for iface in $ifaces; do
        qos_run "tc qdisc delete dev $iface parent root"
    done

    qos_log $LOG_INFO "QoS service finished."
}

qos_atf_show()
{
    echo "------- [wifi0] -------"
    echo wlanconfig "ath50" showatfgroup
    wlanconfig "ath50" showatfgroup
    echo wlanconfig "ath50" showatftable
    wlanconfig "ath50" showatftable
    echo wlanconfig "ath50" showairtime
    wlanconfig "ath50" showairtime
    echo "------- [wifi1] -------"
    echo wlanconfig "ath60" showatfgroup
    wlanconfig "ath60" showatfgroup
    echo wlanconfig "ath60" showatftable
    wlanconfig "ath60" showatftable
    echo wlanconfig "ath60" showairtime
    wlanconfig "ath60" showairtime
}

qos_show ()
{
    qos_atf_show

    for iface in $ifaces; do
        echo "------ [$iface] ------"
        echo "--qdisc--"
        tc -s -d -p qdisc show dev $iface
        echo "---class--"
        tc -s -d -p class show dev $iface
        echo "--filter--"
        tc -s -d -p filter show dev $iface
        echo "------ [END] ------"
    done
    
}

case "$1" in
    start)
        shift 1
        qos_start $@
        ;;
    stop)
        qos_stop
        ;;
    restart)
        qos_stop
        qos_start
        ;;
    show)
        qos_show
        ;;
    add)
        if [ $# -ne 3 -a $# -ne 7 -a $# -ne 8 ]; then
            echo "Usage:"
            echo "    add xx:xx:xx:xx:xx:xx priority"
            echo "    add xx:xx:xx:xx:xx:xx priority wan_tx_up wan_rx_up lan_tx_up lan_rx_up"
            echo "    add xx:xx:xx:xx:xx:xx priority wan_tx_up wan_rx_up lan_tx_up lan_rx_up athXX"
            exit 1
        fi
        shift 1
        qos_add $@
        ;;
    del)
        shift 1
        [ -z $1 ] && echo "Usage: del xx:xx:xx:xx:xx:xx [athxx] " && {exit 1}
        qos_del $@
        ;;
    *)
        echo "Usage: $0 [restart|start|stop|add|del|show]"
        exit 1
        ;;
esac

