#!/bin/sh

id_file="/tmp/qos_client_id"
#ifaces="eth0 wifi0 wifi1"
ifaces="`ifconfig | awk '/ath/{print $1}'` eth0"

line_speed_set="1000mbit 200mbit 1000mbit"
full_speed_set="500mbit 100mbit 500mbit"

LINE_SPEED_eth0="1000mbit"
LINE_SPEED_wifi0="200mbit"
LINE_SPEED_wifi1="1000mbit"
FULL_SPEED_eth0="500mbit"
FULL_SPEED_wifi0="100mbit"
FULL_SPEED_wifi1="500mbit"

AVPKT=1000
CELL=8
ALLOT=1514

run ()
{
    local cmd=$1
    echo "==> ${cmd}"
    $cmd
}

generate_id ()
{
    [ ! -f $id_file ] && touch $id_file

    local seq=`cat $id_file`
    local id=100
    for n in $seq; do
        for m in $seq; do
            if [ $id -eq $m ]; then
                id=$(( id + 1 ))
                break
            fi
        done
    done
    seq="$seq $id"
    echo $seq > $id_file
    echo "$id"
}

mac_to_ip ()
{
    local mac=$1
    local vlan=`sqlite3 /tmp/stationinfo.db "select VLAN from STAINFO where MAC='${mac}';"`
    local ips=`cat /proc/net/arp  | grep "${_mac_}" | grep "br-lan${vlan}" | awk '{print $1}'`
    local client_ip
    if [ -z $ips ]; then
        client_ip=0
    else
        for ip in ${ips}; do
            client_ip=$ip
            break
        done
    fi
    echo "${client_ip}"
}

get_ip ()
{
    local mac=$1
    local rc=`sqlite3 /tmp/stationinfo.db "select IFNAME VLAN from STAINFO where MAC='${mac}' COLLATE NOCASE;"`
    local _ifname
    local _vlan
    OIFS=$IFS;IFS='|';set -- $rc;$_ifname_=$1;$_vlan=$2;IFS=$OIFS
    _vlan="br-lan${_vlan}"
    local ip=`sqlite3 /tmp/arptables.db "select IP from '${vlan}' where MAC='${mac}';"`
    echo "${ip}"
}

cbq_add_classes ()
{
    local iface=$1
    local client_id=$2
    local wt=$3
    #local pri=$(( 1000 - wt ))
    local pri=8
    local limitation=$4
    run "tc class add dev $iface parent 1:1 classid 1:$client_id cbq allot $ALLOT prio $pri avpkt $AVPKT weight $wt rate $limitation"
}

htb_add_classes ()
{
    local iface=$1
    local id=$2
    local wt=$3
    local tx=$4
    local rx=$5

    local param="parent 1:1 classid 1:$id htb burst 15k rate ${wt}00kbit ceil"
    run "tc class add dev $iface $param $rx"
    run "tc class add dev eth0 $param $tx"

    for i in eth0 $iface; do
        run "tc qdisc add dev $i parent 1:$id handle ${id}: sfq perturb 10"
    done
}

add_filters ()
{
    local iface=$1
    local ip=$2
    local id=$3
    local U32="parent 1:0 handle ::${id} protocol ip prio 1 u32"
    run "tc filter add dev $iface ${U32} match ip dst ${ip}/32 flowid 1:$id"
    run "tc filter add dev eth0 ${U32} match ip src ${ip}/32 flowid 1:$id"
}


add ()
{
    # add aa:bb:cc:dd:ee:ff pri tx_up rx_up
    # add aa:bb:cc:dd:ee:ff pri
    local mac=$1
    local pri=$2
    local tx
    [ ! -z $3 ] && tx=$3 || tx=$FULL_SPEED_eth0
    local rx
    [ ! -z $4 ] && rx=$4 || rx=$FULL_SPEED_eth0

    del $mac

    echo "Add client [${mac}] with priority $pri and limitation TX/RX [${tx}/${rx}]."

    local rc=`sqlite3 /tmp/stationinfo.db "select IFNAME,VLAN from STAINFO where MAC='${mac}' COLLATE NOCASE;"`
    #echo "::: $rc :::"
    local ifname
    local vlan
    OIFS=$IFS;IFS='|';set -- $rc;ifname=$1;vlan=$2;IFS=$OIFS
    vlan="br-lan${vlan}"
    #echo ":${ifname}::${vlan}:"
    [ -z $ifname ] && echo "Get interface failed." && return 1
    [ -z $vlan ] && echo "Get VLAN failed." && return 1

    local ip
    for i in 1 2 3; do
        ip=`sqlite3 /tmp/arptables.db "select IP from '${vlan}' where MAC='${mac}' COLLATE NOCASE;"`
        if [ ! -z $ip ]; then
            break
        fi
        sleep 1
    done
    [ -z $ip ] && echo "Get IP failed." && return 1
    
    local id=$( generate_id )
    echo "Generate ID:${id} for client [${ifname}/${ip}/${mac}]."

    #htb_add_classes "eth0" $id $pri $tx
    htb_add_classes $ifname $id $pri $tx $rx
    
    #add_filters "eth0" $ip $id
    add_filters $ifname $ip $id

}

del ()
{
    local mac=$1

    local rc=`sqlite3 /tmp/stationinfo.db "select IFNAME,VLAN from STAINFO where MAC='${mac}' COLLATE NOCASE;"`
    local ifname
    local vlan
    OIFS=$IFS;IFS='|';set -- $rc;ifname=$1;vlan=$2;IFS=$OIFS
    vlan="br-lan${vlan}"
    [ -z $ifname ] && echo "Get interface failed." && return 1
    [ -z $vlan ] && echo "Get VLAN failed." && return 1

    local ip
    for i in 1 2 3; do
        ip=`sqlite3 /tmp/arptables.db "select IP from '${vlan}' where MAC='${mac}' COLLATE NOCASE;"`
        if [ ! -z $ip ]; then
            break
        fi
        sleep 1
    done
    [ -z $ip ] && echo "Get IP failed." && return 1

    local _ip_16_=$(for i in $(echo ${ip} | tr '.' ' '); do printf "%02x" $i; done)
    local id=`tc filter show dev eth0 | grep -B 1 -i "$_ip_16_" | grep "fh" | awk '{print $10}' | awk -F ':' '{print $3}'`

    echo "Delete filter to class ${id}."
    for iface in eth0 $ifname; do
        run "tc filter del dev $iface handle 800::${id} prio 1 protocol ip u32"
    done

    echo "Delete class for client [${ip}/${mac}]."
    for iface in eth0 $ifname; do
        run "tc class del dev $iface classid 1:${id}"
    done

    echo "Release client ID ${id}."
    local _seq_=""
    if [ -f $id_file ]; then
        for pos in `cat $id_file`; do
            if [ $pos -ne ${id} ]; then
                _seq_="$_seq_ $pos"
            fi
        done
        echo ${_seq_} > $id_file
    fi

}

cbq_start_iface ()
{
    local _iface_=$1
    local _line_speed_=$2
    local _full_speed_=$3

    run "tc qdisc add dev $_iface_ root handle 1: cbq avpkt $AVPKT cell $CELL bandwidth $_line_speed_"

    run "tc class add dev $_iface_ parent 1: classid 1:1 cbq allot $ALLOT prio 1 avpkt $AVPKT rate $_full_speed_"
}

cbq_start ()
{
    echo "Kickoff QoS service now."
    touch $id_file

    echo "1. Install CBQ qdisc and root class."
    cbq_start_iface eth0 $LINE_SPEED_eth0 $FULL_SPEED_eth0
    cbq_start_iface wifi0 $LINE_SPEED_wifi0 $FULL_SPEED_wifi0
    cbq_start_iface wifi1 $LINE_SPEED_wifi1 $FULL_SPEED_wifi1

    echo "done"
}

htb_start_iface ()
{
    local _iface_=$1
    local _speed_=$2
    run "tc qdisc add dev $_iface_ root handle 1: htb default 30"
    run "tc class add dev $_iface_ parent 1: classid 1:1 htb rate $_speed_ burst 150k"
    run "tc class add dev $_iface_ parent 1:1 classid 1:30 htb rate 1kbit ceil $_speed_ burst 15k"
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
    echo "Kickoff QoS service now."
    touch $id_file

    echo "1. Install CBQ qdisc and root class."
    local full_speed
    for iface in $ifaces; do
        case "$iface" in
            ath0*)
                full_speed=100mbit
                ;;
            ath1*)
                full_speed=500mbit
                ;;
            *)
                full_speed=900mbit
                ;;
        esac
        #echo $iface $full_speed
        htb_start_iface $iface $full_speed
    done

    echo "done"
}


stop ()
{
    echo "Stop QoS service now."

    echo "1. Remove filter for client."
    for iface in $ifaces; do
        run "tc filter del dev $iface parent 1: protocol ip prio 1 u32"
    done

    echo "2. Remove qdisc and all the classes."
    for iface in $ifaces; do
        run "tc qdisc del dev $iface root"
    done

    rm $id_file
    echo "done"
}

show ()
{
    for iface in $ifaces; do
        echo "<${iface}>:"
        tc qdisc show dev $iface
        tc class show dev $iface
        tc filter show dev $iface
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
        if [ $# -ne 3 -a $# -ne 5 ]; then
            echo "Usage:"
            echo "    add xx:xx:xx:xx:xx:xx priority"
            echo "    add xx:xx:xx:xx:xx:xx priority tx_up rx_up"
            exit 1
        fi
        shift 1
        add $@
        ;;
    del)
        shift 1
        [ -z $1 ] && echo "Usage: del xx:xx:xx:xx:xx:xx" && exit 1
        del $1
        ;;
    *)
        echo "Usage: $0 [restart|start|stop|add|del|show]"
        exit 1
        ;;
esac

