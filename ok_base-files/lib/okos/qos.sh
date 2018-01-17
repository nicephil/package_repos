#!/bin/sh

LOG_MERG=0
LOG_NOTICE=4
LOG_WARNING=5
LOG_INFO=6
LOG_DEBUG=7
log ()
{
    local pri=$1
    shift 1
    echo "$@" | logger -t qosscript -p $pri
}
run ()
{
    local cmd=$1
    echo "==> ${cmd}" | logger -t qosscript -p $LOG_DEBUG
    [ -z "$debug" ] && eval "$cmd"
}

qos_trap ()
{
    log $LOG_DEBUG "QoS Trapped."
    lock -u /var/run/qos.lock
}
trap 'qos_trap; exit' INT TERM ABRT QUIT ALRM

lock /var/run/qos.lock

#debug=True
QDISC="htb"
#QDISC="hfsc"

id_file="/tmp/qos_client_id"
id_base=100
sta_db="/tmp/stationinfo.db"
sta_table="STAINFO"
#arp_file="/proc/net/arp"

if [ ! -z "$debug" ]; then
    ifaces="ath00 ath10 ath01 ath11 eth0"
else
    ifaces="`ifconfig | awk '/ath/{print $1}'` eth0"
fi
[ ! -z "$debug" ] && echo "interfaces: $ifaces "

FULL_SPEED_eth0="500000"

#generate_id ()
#{
#    [ ! -f $id_file ] && echo >&2 "$id_flie is absent, create new one." &&  touch $id_file
#
#    local seq=`cat $id_file`
#    local id=100
#    for n in $seq; do
#        for m in $seq; do
#            if [ $id -eq $m ]; then
#                id=$(( id + 1 ))
#                break
#            fi
#        done
#    done
#    seq="$seq $id"
#    echo $seq > $id_file
#    echo "$id"
#}

#####################################################
# Format of ID file: /tmp/qos_client_id
# -------------------------------------------------
# MAC               IP              Interface   ID
# fc:ad:0f:06:a3:28 192.168.254.193 ath11       104
# f0:b4:29:c7:70:da 192.168.254.173 ath01       105
# f4:0f:24:2d:da:08 192.168.254.141 ath10       106
#
#####################################################

get_id ()
{
    [ ! -f $id_file ] && log $LOG_DEBUG "$id_file is absent, create new one." &&  touch $id_file
    log $LOG_DEBUG "get_id(): for $mac ."

    local mac=$1

    local ck=`grep -i "${mac}" ${id_file}`
    log $LOG_DEBUG "get_id(): $ck ."

    # Reture entry corresponding to given MAC.
    echo "${ck}"
}

new_id ()
{
    local mac=`echo $1 | tr 'A-Z' 'a-z'`
    local ip=$2
    local ifname=$3
    log $LOG_DEBUG "new_id(): ( MAC:$mac , IP:$ip , IFNAME:$ifname )"

    local id=$id_base
    local ids=`cat $id_file | awk '{print $4}'`
    for n in $ids; do
        for m in $ids; do
            if [ $id -eq $m ]; then
                id=$(( id + 1 ))
                break
            fi
        done
    done

    echo "$mac $ip $ifname $id" >> $id_file
    log $LOG_DEBUG "new_id(): get ID:$id ."

    echo "${id}"
}

del_id ()
{
    local id=$1
    log $LOG_DEBUG "del_id(): ID:$id "
    sed -i "/ ${id}$/d" ${id_file}

    log $LOG_DEBUG "del_id(): done."
}


del_id_by_mac ()
{
    local mac=$1
    log $LOG_DEBUG "del_id_by_mac(): MAC:$mac "
    sed -i "/^${mac} /d" ${id_file}

    log $LOG_DEBUG "del_id_by_mac(): done."
}

###############################################################################
# INPUT:
#   1. MAC
#   2. ifname (optional)
# OUTPUT:
#   1. IP
#   2. ifname
#
###############################################################################

get_ip ()
{
    local mac=$1
    local ifname=$2
    log $LOG_DEBUG "get_ip(): MAC:$mac IFNAME:$ifname "

    local rc
    local ip

    log $LOG_DEBUG "get_ip(): try to get ip by MAC:$mac from $sta_db ."
    ip=`sqlite3 $sta_db "select IPADDR from '${sta_table}' where MAC='${mac}' COLLATE NOCASE;"`
    [ -z "$ip" ] && log $LOG_DEBUG "Get IP from $sta_db failed." && echo "" && return 1
    
    log $LOG_DEBUG "get_ip(): output=>IP:$ip , IFNAME:$ifname ."
    echo "${ip} ${ifname}"
    return 0
}

hfsc_add_classes ()
{
    local iface=$1
    local id=$2
    local wt=$3
    local tx=$4
    local rx=$5

    local param="parent 1:1 classid 1:$id hfsc ls m2 ${wt}00kbit ul m2"
    run "tc class add dev $iface $param $rx"
    run "tc class add dev eth0 $param $tx"

    for i in eth0 $iface; do
        run "tc qdisc add dev $i parent 1:$id handle ${id}: sfq perturb 10"
    done
}

htb_change_classes ()
{
    local iface=$1
    local id=$2
    local wt=$3
    local tx=$4
    local rx=$5

    local param="parent 1:1 classid 1:$id htb burst 15k rate ${wt}00kbit ceil"
    run "tc class change dev $iface $param $rx"
    run "tc class change dev eth0 $param $tx"
}

htb_add_classes ()
{
    local iface=$1
    local id=$2
    local wt=$3
    local tx=$4
    local rx=$5
    local lan_tx=$6
    local lan_rx=$7

    # WAN downlink
    local param="parent 1:1 classid 1:$id htb burst 15k rate $((${wt}*12))kbit ceil"
    run "tc class add dev $iface $param $rx"
    # WAN uplink
    run "tc class add dev eth0 $param $tx"

    # LAN downlink
    local param="parent 1:1 classid 1:1$id htb burst 15k rate $((${wt}*12))kbit ceil"
    run "tc class add dev $iface $param $lan_rx"
    # LAN uplink on all ifaces
    local param="parent 1:1 classid 1:2$id htb burst 15k rate $((${wt}*12))kbit ceil"
    for iface in ${ifaces}
    do
        run "tc class add dev $iface $param $lan_tx"
    done
}

ip2int()
{
    local A=$(echo $1 | cut -d '.' -f1)
    local B=$(echo $1 | cut -d '.' -f2)
    local C=$(echo $1 | cut -d '.' -f3)
    local D=$(echo $1 | cut -d '.' -f4)
    local result=$(($A<<24|$B<<16|$C<<8|$D))
    echo $result
}

add_filters ()
{
    local iface=$1
    local ip=$2
    local id=$3
    local ip_int="$(ip2int $ip)"
    ip_int="$(printf %04x $ip_int)"

    # WAN downlink
    local wan_downlink_ematch="not u32(u32 0xc0a80000 0xffff0000 at 12) and not u32(u32 0xac100000 0xfff00000 at 12) and not u32(u32 0x0a000000 0xff000000 at 12)"
    local wan_downlink_ip_ematch="u32(u16 0x${ip_int:0:4} 0xffff at 16) and u32(u16 0x${ip_int:4} 0xffff at 18)"
    local ematch="prio ${id} protocol ip basic match '${wan_downlink_ematch} and ${wan_downlink_ip_ematch}'"
    run "tc filter add dev $iface parent 1:0 ${ematch} flowid 1:${id}"

    # WAN uplink
    local wan_uplink_ematch="not u32(u32 0xc0a80000 0xffff0000 at 16) and not u32(u32 0xac100000 0xfff00000 at 16) and not u32(u32 0x0a000000 0xff000000 at 16)"
    local wan_uplink_ip_ematch="u32(u16 0x${ip_int:0:4} 0xffff at 12) and u32(u16 0x${ip_int:4} 0xffff at 14)"
    local ematch="prio ${id} protocol ip basic match '${wan_uplink_ip_ematch} and ${wan_uplink_ematch}'"
    run "tc filter add dev eth0 parent 1:0 ${ematch} flowid 1:${id}"

    # LAN downlink
    local lan_downlink_ematch="u32(u32 0xc0a80000 0xffff0000 at 12) or u32(u32 0xac100000 0xfff00000 at 12) or u32(u32 0x0a000000 0xff000000 at 12)"
    local lan_downlink_ip_ematch="u32(u16 0x${ip_int:0:4} 0xffff at 16) and u32(u16 0x${ip_int:4} 0xffff at 18)"
    local ematch="prio 1${id} protocol ip basic match '${lan_downlink_ematch} and ${lan_downlink_ip_ematch}'"
    run "tc filter add dev $iface parent 1:0 ${ematch} flowid 1:1${id}"

    # LAN uplink on all ifaces
    local lan_uplink_ematch="u32(u32 0xc0a80000 0xffff0000 at 16) or u32(u32 0xac100000 0xfff00000 at 16) or u32(u32 0x0a000000 0xff000000 at 16)"
    local lan_uplink_ip_ematch="u32(u16 0x${ip_int:0:4} 0xffff at 12) and u32(u16 0x${ip_int:4} 0xffff at 14)"
    local ematch="prio 2${id} protocol ip basic match '${lan_uplink_ip_ematch} and ${lan_uplink_ematch}'"
    for _iface in ${ifaces}
    do
        run "tc filter add dev $_iface parent 1:0 ${ematch} flowid 1:2${id}"
    done
}


#add_o1 ()
#{
#    # add aa:bb:cc:dd:ee:ff pri tx_up rx_up
#    # add aa:bb:cc:dd:ee:ff pri
#    local mac=$1
#    local pri=$2
#    local tx
#    [ ! -z $3 ] && tx=$3 || tx=$FULL_SPEED_eth0
#    [ $tx -eq 0 ] && tx=$FULL_SPEED_eth0
#    tx="${tx}kbit"
#    local rx
#    [ ! -z $4 ] && rx=$4 || rx=$FULL_SPEED_eth0
#    [ $rx -eq 0 ] && rx=$FULL_SPEED_eth0
#    rx="${rx}kbit"
#    local ifname=$5
#
#    local rc
#    local ip
#    local ip2
#    local ifname2
#    local id
#    local id2
#
#    log $LOG_INFO "Add client [${mac}] on <${ifname}> with priority $pri and limitation TX/RX [${tx}/${rx}]."
#
#    rc=$( get_ip $mac $ifname )
#    log $LOG_DEBUG "get_ip()=>$rc <"
#    [ -z "$rc" ] && log $LOG_WARNING "Get IP failed." && return 1
#    OIFS=$IFS;IFS=' ';set -- $rc;ip=$1;ifname=$2;IFS=$OIFS
#    log $LOG_DEBUG "Add: Get IP:$ip & IFNAME:$ifname ."
#    
#    #local id=$( generate_id )
#    rc=$( get_id $mac )
#    log $LOG_DEBUG "get_id()=>$rc <"
#    if [ ! -z "$rc" ]; then
#        OIFS=$IFS;IFS=' ';set -- $rc;_=$1;ip2=$2;ifname2=$3;id=$4;IFS=$OIFS
#        log $LOG_DEBUG "Client exists in $id_file {MAC:$mac , ID:$id , IP:$ip2 , IFNAME:$ifname2 }."
#        if [ "$ip" == "$ip2" -a "$ifname" == "$ifname2" ]; then
#            log $LOG_DEBUG "Client info(ip & ifname) in $id_file match input."
#            local id2=$( chk_hw_id_by_ip $ip )
#            log $LOG_DEBUG "chk_hw_id_by_ip()=>$id2 <search id by ip in filter."
#            if [ "$id" == "$id2" ]; then
#                log $LOG_INFO "Client ID match ID in hardware, just change the setting."
#                ${QDISC}_change_classes $ifname $id $pri $tx $rx 
#                return 0
#            else
#                log $LOG_INFO "ID got from $id_file doesn't exist in hardward."
#                log $LOG_DEBUG "Delete client in TC by ID:$id2 ."
#                del_tc_by_id_ifname $id2
#            fi
#        else
#            log $LOG_INFO "Client info dones't match $id_file "
#            log $LOG_DEBUG "Delete client in TC by $id_file info: IP:$ip2 & IFNAME:$ifname2 "
#            del_tc_by_ip_ifname $ip2 $ifname2
#        fi
#
#        log $LOG_DEBUG "Release client ID by MAC: ${mac}."
#        del_id_by_mac "$mac"
#    fi
#    
#    id=$( new_id $mac $ip $ifname )
#    log $LOG_DEBUG "Generate ID:${id} for client [${ifname}/${ip}/${mac}]."
#    ${QDISC}_add_classes $ifname $id $pri $tx $rx
#    add_filters $ifname $ip $id
#
#    log $LOG_INFO "Add client done"
#}

add ()
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

    local rc
    local ip
    local id

    log $LOG_INFO "Add client [${mac}] on <${ifname}> with priority $pri and limitation WAN TX/RX [${tx}/${rx}] LAN TX/RX [${lan_tx}/${lan_rx}]."

    log $LOG_DEBUG "Del client by ${mac}."
    del $mac

    rc=$( get_ip $mac $ifname )
    log $LOG_DEBUG "get_ip()=>$rc <"
    [ -z "$rc" ] && log $LOG_WARNING "Get IP failed and exit." && return 1
    OIFS=$IFS;IFS=' ';set -- $rc;ip=$1;ifname=$2;IFS=$OIFS
    log $LOG_DEBUG "Add: Get IP:$ip & IFNAME:$ifname ."
    
    id=$( new_id $mac $ip $ifname )
    log $LOG_DEBUG "Generate ID:${id} for client [${ifname}/${ip}/${mac}]."
    ${QDISC}_add_classes $ifname $id $pri $tx $rx $lan_tx $lan_rx
    add_filters $ifname $ip $id

    log $LOG_INFO "Add client done"
}

chk_hw_id_by_ip ()
{
    local ip=$1
    log $LOG_DEBUG "chk_hw_id_by_ip(): for IP:$ip "

    local _ip_16_=$(for i in $(echo ${ip} | tr '.' ' '); do printf "%02x" $i; done)
    local id
    
    if [ ! -z "$debug" ]; then
        id=100
    else
        id=`tc filter show dev eth0 | grep -B 1 -i "$_ip_16_" | grep "fh" | awk '{print $10}' | awk -F ':' '{print $3}'`
    fi

    log $LOG_DEBUG "chk_hw_id_by_ip()=> get id:$id "
    echo "${id}"
}


del_tc_by_id_ifname ()
{
    local id=$1
    local ifname=$2
    log $LOG_DEBUG "del_tc_by_id_ifname(): ID:$id IFNAME:$ifname "

    log $LOG_DEBUG "Delete filter to class ${id}."
    # del WAN related
    for iface in eth0 $ifname; do
        run "tc filter del dev $iface parent 1:0 prio ${id}"
    done
    # del LAN related
    for iface in ${ifaces}; do
        if [ "$iface" = "$ifname" ]
        then
            run "tc filter del dev $iface parent 1:0 prio 1${id}"
            run "tc filter del dev $iface parent 1:0 prio 2${id}"
        else
            run "tc filter del dev $iface parent 1:0 prio 2${id}" 
        fi
    done

    log $LOG_DEBUG "Delete class for client [${id}]."
    # del WAN related
    for iface in eth0 $ifname; do
        run "tc class del dev $iface classid 1:${id}"
    done
    # del LAN related
    for iface in ${ifaces}; do
        if [ "$iface" = "$ifname" ]
        then
            run "tc class del dev $iface classid 1:1${id}"
            run "tc class del dev $iface classid 1:2${id}"
        else
            run "tc class del dev $iface classid 1:2${id}"
        fi
    done

    log $LOG_DEBUG "del_tc_by_id_ifname(): done."
}

del_tc_by_ip_ifname ()
{
    local ip=$1
    local ifname=$2
    log $LOG_DEBUG "del_tc_by_ip_ifname(): IP:$ip IFNAME:$ifname "

    local id=$( chk_hw_id_by_ip $ip )
    log $LOG_DEBUG "del_tc_by_ip_ifname(): get ID:$id from chk_hw_id_by_ip( $ip )."


    log $LOG_DEBUG "Delete client by ID:$id IFNAME:$ifname "
    del_tc_by_id_ifname $id $ifname
    log $LOG_DEBUG "del_tc_by_ip_ifname(): done."
}

#del_o1 ()
#{TTTTT
#    local mac=$1
#    local ifname=$2
#    log $LOG_DEBUG "Del: $@ ."
#    local ip2
#    local ifname2
#    local ip3
#    local ifname3
#    local rc2
#    local rc3
#
#    rc2=$( get_id $mac )
#    if [ ! -z "$rc2" ]; then
#        OIFS=$IFS;IFS=' ';set -- $rc2;_=$1;ip2=$2;ifname2=$3;id=$4;IFS=$OIFS
#        log $LOG_DEBUG "Del(): get_id( $mac ) => IP:$ip2 IFNAME:$ifname2 ID:$id ."
#    fi
#    rc3=$( get_ip $mac $ifname )
#    if [ ! -z "$rc3" ]; then
#        OIFS=$IFS;IFS=' ';set -- $rc3;ip3=$1;ifname3=$2;IFS=$OIFS
#        log $LOG_DEBUG "Del(): get_ip( $mac , $ifname ) => IP:$ip3 IFNAME:$ifname3 ."
#    fi
#
#    if [ -z "$rc2" -a -z "$rc3" ]; then
#        log $LOG_DEBUG "Don't know how to delet $mac on interface $iface ."
#    elif [ ! -z "$rc2" -a -z "$rc3" ]; then
#        del_tc_by_id_ifname $id $ifname2
#    elif [ ! -z "$rc3" -a -z "$rc2" ]; then
#        del_tc_by_ip_ifname $ip3 $ifname3
#    elif [ "$ip2" == "$ip3" -a "$ifname2" == "$ifname3" ]; then
#        del_tc_by_id_ifname $id $ifname2
#    else
#        del_tc_by_ip_ifname $ip2 $ifname2
#    fi
#
#    log $LOG_DEBUG "Release client ID by MAC: ${mac}."
#    del_id_by_mac "$mac"
#
#    log $LOG_DEBUG "Del(): done."
#}

del ()
{
    local mac=`echo $1 | tr 'A-Z' 'a-z'`
    local ifname=$2
    log $LOG_DEBUG "Del: $@ ."

    local rc2
    local ip2
    local ifname2
    local id2

    rc2=$( get_id $mac )
    if [ ! -z "$rc2" ]; then
        OIFS=$IFS;IFS=' ';set -- $rc2;_=$1;ip2=$2;ifname2=$3;id2=$4;IFS=$OIFS
        log $LOG_DEBUG "Del(): get_id( $mac ) => IP:$ip2 IFNAME:$ifname2 ID:$id2 ."
    fi

    if [ -z "$rc2" ]; then
        log $LOG_DEBUG "Don't know how to delete $mac on interface $iface ."
    else
        del_tc_by_id_ifname $id2 $ifname2
    fi

    log $LOG_DEBUG "Release client ID by MAC: ${mac}."
    del_id_by_mac "$mac"

    log $LOG_DEBUG "Del(): done."
}

hfsc_start_iface ()
{
    local _iface_=$1
    local _speed_=${2}bit
    run "tc qdisc add dev $_iface_ root handle 1: hfsc default 30"
    run "tc class add dev $_iface_ parent 1: classid 1:1 hfsc ls m2 $_speed_"
    run "tc class add dev $_iface_ parent 1:1 classid 1:30 hfsc ls m2 100kbps ul m2 $_speed_"
    run "tc qdisc add dev $_iface_ parent 1:30 handle 30: sfq perturb 10"
}

htb_start_iface ()
{
    local _iface_=$1
    local _speed_="${2}bit"
    run "tc qdisc add dev $_iface_ root handle 1: htb default 30 r2q 1"
    run "tc class add dev $_iface_ parent 1:0 classid 1:1 htb rate $_speed_ ceil $_speed_ burst 150k"
    # default class
    run "tc class add dev $_iface_ parent 1:1 classid 1:30 htb rate 12kbit ceil $_speed_ burst 150k"
    run "tc qdisc add dev $_iface_ parent 1:30 handle 30: sfq perturb 10"
}

thtb_start_iface ()
{
    local _iface_=$1
    local _speed_=$2
    run "tc qdisc add dev $_iface_ root handle 10: htb default 30"
    run "tc class add dev $_iface_ parent 10: classid 10:1 htb rate $_speed_ burst 150k"
    run "tc class add dev $_iface_ parent 10:1 classid 10:30 htb rate 1kbit ceil $_speed_ burst 15k"
    run "tc qdisc add dev $_iface_ parent 10:1 handle 1: htb default 30"
    run "tc class add dev $_iface_ parent 1: classid 1:1 htb rate $_speed_ burst 150k"
    run "tc class add dev $_iface_ parent 1:1 classid 1:30 htb rate 1kbit ceil $_speed_ burst 15k"
}


start ()
{
    log $LOG_INFO "Kickoff QoS service now."
    log $LOG_DEBUG "Touch $id_file for restoring client ID infor."
    touch $id_file

    log $LOG_DEBUG "Install $QDISC qdisc and root class."
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
        #echo $iface $full_speed
        ${QDISC}_start_iface $iface $full_speed
    done

    log $LOG_INFO "QoS service done."
}


stop ()
{
    log $LOG_INFO "Stop QoS service now."

    log $LOG_INFO "1. Remove root."
    for iface in $ifaces; do
        run "tc qdisc delete dev $iface parent root"
    done

    log $LOG_DEBUG "Client id file $id_file removed."
    rm $id_file 2>/dev/null
    log $LOG_INFO "QoS service finished."
}

show ()
{
    for iface in $ifaces; do
        echo "------ [$iface] ------"
        tc -s -d -p qdisc show dev $iface
        tc -s -d -p class show dev $iface
        tc -s -d -p filter show dev $iface
        echo "------ [END] ------"
    done
    
}

case "$1" in
    start)
        shift 1
        start $@
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    show)
        show
        ;;
    add)
        if [ $# -ne 3 -a $# -ne 7 -a $# -ne 8 ]; then
            echo "Usage:"
            echo "    add xx:xx:xx:xx:xx:xx priority"
            echo "    add xx:xx:xx:xx:xx:xx priority wan_tx_up wan_rx_up lan_tx_up lan_rx_up"
            echo "    add xx:xx:xx:xx:xx:xx priority wan_tx_up wan_rx_up lan_tx_up lan_rx_up athXX"
            lock -u /var/run/qos.lock
            exit 1
        fi
        shift 1
        add $@
        ;;
    del)
        shift 1
        [ -z $1 ] && echo "Usage: del xx:xx:xx:xx:xx:xx [athxx] " && exit 1
        del $@
        ;;
    *)
        echo "Usage: $0 [restart|start|stop|add|del|show]"
        lock -u /var/run/qos.lock
        exit 1
        ;;
esac

lock -u /var/run/qos.lock
