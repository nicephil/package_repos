#!/bin/sh

#debug=True
QDISC="htb"
#QDISC="hfsc"

id_file="/tmp/qos_client_id"
id_base=100
arp_db="/tmp/arptables.db"
sta_db="/tmp/stationinfo.db"
arp_file="/proc/net/arp"

if [ ! -z "$debug" ]; then
    ifaces="ath00 ath10 ath01 ath11 eth0"
else
    ifaces="`ifconfig | awk '/ath/{print $1}'` eth0"
fi
[ ! -z "$debug" ] && echo "interfaces: $ifaces "

FULL_SPEED_eth0="500000"

run ()
{
    local cmd=$1
    echo "==> ${cmd}"
    [ -z "$debug" ] && $cmd
}

generate_id ()
{
    [ ! -f $id_file ] && echo >&2 "$id_flie is absent, create new one." &&  touch $id_file

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

get_id ()
{
    [ ! -f $id_file ] && echo >&2 "$id_file is absent, create new one." &&  touch $id_file
    [ ! -z "$debug" ] && echo >&2 "get_id(): for $mac ."

    local mac=$1
    local ck=`grep "${mac}" ${id_file}`
    [ ! -z "$debug" ] && echo >&2 "get_id(): $ck ."

    echo "${ck}"
}

new_id ()
{
    local mac=$1
    local ip=$2
    local ifname=$3
    [ ! -z "$debug" ] && echo >&2 "new_id(): ( MAC:$mac , IP:$ip , IFNAME:$ifname )"

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
    [ ! -z "$debug" ] && echo >&2 "new_id(): get ID:$id ."

    echo "${id}"
}

del_id ()
{
    local id=$1
    [ ! -z "$debug" ] && echo >&2 "del_id(): ID:$id "
    sed -i "/ ${id}$/d" ${id_file}

    [ ! -z "$debug" ] && echo >&2 "del_id(): done."
}


del_id_by_mac ()
{
    local mac=$1
    [ ! -z "$debug" ] && echo >&2 "del_id_by_mac(): MAC:$mac "
    sed -i "/^${mac} /d" ${id_file}

    [ ! -z "$debug" ] && echo >&2 "del_id_by_mac(): done."
}

get_ip ()
{
    local mac=$1
    local ifname=$2
    [ ! -z "$debug" ] && echo >&2 "get_ip(): MAC:$mac IFNAME:$ifname "

    local rc
    local vlan
    local ip
    if [ -z "$ifname" ]; then
        rc=`sqlite3 $sta_db "select IFNAME,VLAN from STAINFO where MAC='${mac}' COLLATE NOCASE;"`
        OIFS=$IFS;IFS='|';set -- $rc;ifname=$1;vlan=$2;IFS=$OIFS
        vlan="br-lan${vlan}"
        echo >&2 "get_ip(): got IFNAME:$ifname and VLAN:$vlan from $sta_db ."

        [ -z "$ifname" ] && echo >&2 "Get IFNAME from $sta_db failed." && echo "" && return 1
        [ -z "$vlan" ] && echo >&2 "Get VLAN from $sta_db failed." && echo "" && return 1
    else
        if [ ! -z "$debug" ]; then
            rc="'lan3000'"
        else
            rc=`uci -q show wireless.${ifname}.network`
        fi
        [ -z "$rc" ] && echo >&2 "Get IFNAME from uci failed." && echo "" && return 1
        vlan=`echo $rc | awk -F "'" '{print $2}'`
        vlan="br-${vlan}"
        echo >&2 "get_ip(): got VLAN:$vlan by IFNAME:$ifname from uci."
    fi

    [ ! -z "$debug" ] && echo >&2 "get_ip(): try to get ip by MAC:$mac and VLAN:$vlan from $arp_db ."
    for i in 1 2 3; do
        ip=`sqlite3 $arp_db "select IP from '${vlan}' where MAC='${mac}' COLLATE NOCASE;"`
        [ ! -z "$ip" ] && break
        sleep 1
    done
    [ -z "$ip" ] && echo >&2 "Get IP from $arp_db failed." && echo "" && return 1
    
    [ ! -z "$debug" ] && echo >&2 "get_ip(): output=>IP:$ip , IFNAME:$ifname ."
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
    [ $tx -eq 0 ] && tx=$FULL_SPEED_eth0
    tx="${tx}kbit"
    local rx
    [ ! -z $4 ] && rx=$4 || rx=$FULL_SPEED_eth0
    [ $rx -eq 0 ] && rx=$FULL_SPEED_eth0
    rx="${rx}kbit"
    local ifname=$5
    [ ! -z "$debug" ] && echo >&2 "add(): $@ => $mac , $pri , $tx , $rx , $ifname ."

    local rc
    local ip
    local ip2
    local ifname2
    local id
    local id2

    echo >&2 "Add client [${mac}] on <${ifname}> with priority $pri and limitation TX/RX [${tx}/${rx}]."

    rc=$( get_ip $mac $ifname )
    [ ! -z "$debug" ] && echo >&2 "get_ip()=>$rc <"
    [ -z "$rc" ] && echo >&2 "Get IP failed." && return 1
    OIFS=$IFS;IFS=' ';set -- $rc;ip=$1;ifname=$2;IFS=$OIFS
    [ ! -z "$debug" ] && echo >&2 "Add: Get IP:$ip & IFNAME:$ifname ."
    
    #local id=$( generate_id )
    rc=$( get_id $mac )
    [ ! -z "$debug" ] && echo >&2 "get_id()=>$rc <"
    if [ ! -z "$rc" ]; then
        OIFS=$IFS;IFS=' ';set -- $rc;_=$1;ip2=$2;ifname2=$3;id=$4;IFS=$OIFS
        echo >&2 "Client exists in $id_file {MAC:$mac , ID:$id , IP:$ip2 , IFNAME:$ifname2 }."
        if [ "$ip" == "$ip2" -a "$ifname" == "$ifname2" ]; then
            echo >&2 "Client info in $id_file match input."
            local id2=$( chk_hw_id $ip )
            [ ! -z "$debug" ] && echo >&2 "chk_hw_id()=>$id2 <"
            if [ "$id" == "$id2" ]; then
                echo >&2 "Client ID match ID in hardware, just change the setting."
                ${QDISC}_change_classes $ifname $id $pri $tx $rx 
                return 0
            else
                echo >&2 "ID got from $id_file doesn't exist in hardward."
                echo >&2 "Delete client in TC by ID:$id2 ."
                _del_by_id $id2
            fi
        else
            echo >&2 "Client info dones't match $id_file "
            echo >&2 "Delete client in TC by $id_file info: IP:$ip2 & IFNAME:$ifname2 "
            _del $ip2 $ifname2
        fi

        echo "Release client ID by MAC: ${mac}."
        del_id_by_mac "$mac"

    fi
    
    id=$( new_id $mac $ip $ifname )
    echo >&2 "Generate ID:${id} for client [${ifname}/${ip}/${mac}]."
    ${QDISC}_add_classes $ifname $id $pri $tx $rx
    add_filters $ifname $ip $id

    echo >&2 "done"
}

chk_hw_id ()
{
    local ip=$1
    [ ! -z "$debug" ] && echo >&2 "chk_hw_id(): for IP:$ip "

    local _ip_16_=$(for i in $(echo ${ip} | tr '.' ' '); do printf "%02x" $i; done)
    local id
    
    if [ ! -z "$debug" ]; then
        id=100
    else
        id=`tc filter show dev eth0 | grep -B 1 -i "$_ip_16_" | grep "fh" | awk '{print $10}' | awk -F ':' '{print $3}'`
    fi

    [ ! -z "$debug" ] && echo >&2 "chk_hw_id()=> get id:$id "
    echo "${id}"
}


_del_by_id ()
{
    local id=$1
    local ifname=$2
    [ ! -z "$debug" ] && echo >&2 "_del_by_id(): ID:$id IFNAME:$ifname "

    echo "Delete filter to class ${id}."
    for iface in eth0 $ifname; do
        run "tc filter del dev $iface handle 800::${id} prio 1 protocol ip u32"
    done

    echo "Delete class for client [${id}]."
    for iface in eth0 $ifname; do
        run "tc class del dev $iface classid 1:${id}"
    done

    [ ! -z "$debug" ] && echo >&2 "_del_by_id(): done."
}

_del ()
{
    local ip=$1
    local ifname=$2
    [ ! -z "$debug" ] && echo >&2 "_del(): IP:$ip IFNAME:$ifname "

    local id=$( chk_hw_id $ip )
    [ ! -z "$debug" ] && echo >&2 "_del(): get ID:$id from chk_hw_id( $ip )."


    echo >&2 "Delete client by ID:$id IFNAME:$ifname "
    _del_by_id $id $ifname
    [ ! -z "$debug" ] && echo >&2 "_del(): done."
}

del ()
{
    local mac=$1
    local ifname=$2
    [ ! -z "$debug" ] && echo "Del: $@ ."
    local ip2
    local ifname2
    local ip3
    local ifname3
    local rc2
    local rc3

    rc2=$( get_id $mac )
    if [ ! -z "$rc2" ]; then
        OIFS=$IFS;IFS=' ';set -- $rc2;_=$1;ip2=$2;ifname2=$3;id=$4;IFS=$OIFS
        echo >&2 "Del(): get_id( $mac ) => IP:$ip2 IFNAME:$ifname2 ID:$id ."
    fi
    rc3=$( get_ip $mac $ifname )
    if [ ! -z "$rc3" ]; then
        OIFS=$IFS;IFS=' ';set -- $rc3;ip3=$1;ifname3=$2;IFS=$OIFS
        echo >&2 "Del(): get_ip( $mac , $ifname ) => IP:$ip3 IFNAME:$ifname3 ."
    fi

    if [ -z "$rc2" -a -z "$rc3" ]; then
        echo "Don't know how to delet $mac on interface $iface ."
    elif [ ! -z "$rc2" -a -z "$rc3" ]; then
        _del_by_id $id $ifname2
    elif [ ! -z "$rc3" -a -z "$rc2" ]; then
        _del $ip3 $ifname3
    elif [ "$ip2" == "$ip3" -a "$ifname2" == "$ifname3" ]; then
        _del_by_id $id $ifname2
    else
        _del $ip2 $ifname2
    fi

    echo "Release client ID by MAC: ${mac}."
    del_id_by_mac "$mac"

    [ ! -z "$debug" ] && echo >&2 "Del(): done."
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

    echo "1. Install $QDISC qdisc and root class."
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
        if [ $# -ne 3 -a $# -ne 5 -a $# -ne 6 ]; then
            echo "Usage:"
            echo "    add xx:xx:xx:xx:xx:xx priority"
            echo "    add xx:xx:xx:xx:xx:xx priority tx_up rx_up"
            echo "    add xx:xx:xx:xx:xx:xx priority tx_up rx_up athXX"
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
        exit 1
        ;;
esac

