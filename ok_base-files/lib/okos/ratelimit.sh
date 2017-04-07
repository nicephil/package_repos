#!/bin/sh

help()
{
    cat <<HELP
Rate limit per SSID and Client.
Usage: ratelimit [-hiblrs] target
         -h ## Show this help.
         -i INTERFACE ## The interface should be applied rate limitation
         -b UPLINK DOWNLINK ## Uplink and downlink bandwidth of athX
         -l UPLOAD DOWNLOAD ## Upload and download bandwidth of each client
         -r INTERFACE ## Remove the ratelimitation
         -s INTERFACE ## Show Status
Example: ratelimit -i ath01 -b 5m 20m ## Limit uplink rate is 5mbps; downlink is 20mbps on ath01
         ratelimit -i ath11 -l 512k 4m ## Limit uplink rate of clients on ath11 is 512kbps and downlink is 4mbps
         ratelimit -r ath00 ## Remove all the rate limitation

HELP
    exit 0
}


while [ -n "$1" ]; do
    case $1 in
        -h) help;shift 1;;
        -i) action='start';IFACE="$2";shift 2;;
        -b) UPLINK="$2";DOWNLINK="$3";shift 3;;
        -l) UPLOAD="$2";DOWNLOAD="$3";shift 3;;
        -r) action='stop';IFACE="$2";shift 2;;
        -s) action='status';IFACE="$2";shift 2;;
        --) shift;break;;
        -*) echo "error: no such option $1. -h for help";exit 1;;
        *) break;;
    esac
done

[ -z "$action" ] && echo "Oops.. What do you want?" && exit 1

if [ ${action} = "status" ]; then
    echo "Show status on $IFACE"
    tc -s qdisc ls dev $IFACE
    tc -s class ls dev $IFACE
    exit
fi

if [ ${action} = "stop" ]; then
    echo "Stop service on $IFACE"
    tc qdisc del dev $IFACE root    2> /dev/null > /dev/null
    tc qdisc del dev $IFACE ingress 2> /dev/null > /dev/null
    exit
fi


[ -z "$IFACE" ] && echo "Error: Could not find the device, aborting." && exit 1



if [ ! -z "$UPLINK" -o ! -z "$DOWNLINK" ]; then
    echo "Start to add rate limitation [${UPLINK}bit/s, ${DOWNLINK}bit/s] on $IFACE."

    ######## Uplink limit for athXY ########
    #  Traffice Policy at Ingress ath xx.  #
    ########################################
    echo "Uplink => ingress qdisc"
    tc qdisc add dev $IFACE handle ffff: ingress
    echo "Uplink => filter 0/0 drop"
    tc filter add dev $IFACE parent ffff: protocol ip prio 500 u32 \
        match ip src 0.0.0.0/0 \
        police rate ${UPLINK}bit burst 15k drop flowid :1

    ######## Downlink limit for athXY ########
    #        Hierachical Token Bucket.       #
    ##########################################
    echo "Downlink <= root"
    tc qdisc add dev $IFACE root handle 1: htb default 9999
    echo "Downlink <= class htb"
    tc class add dev $IFACE parent 1: classid 1:1 htb rate ${DOWNLINK}bit burst 15k
    echo "Downlink <= class default"
    tc class add dev $IFACE parent 1:1 classid 1:9999 htb rate ${DOWNLINK}bit burst 15k
    echo "Downlink <= qdisc default sfq"
    tc qdisc add dev $IFACE parent 1:9999 handle 9999: sfq perturb 10
    echo "Downlink <= filter 0/0 -> default"
    tc filter add dev $IFACE protocol ip parent 1:0 prio 1000 u32 match ip src 0.0.0.0/0 flowid 1:9999

    exit
fi

if [ ! -z "$UPLOAD" -o ! -z "$DOWNLOAD" ]; then
    echo "Start to add rate limitation [${UPLOAD}bit/s, ${DOWNLOAD}bit/s] for clients on $IFACE."

    ######## Uplink limit for clients ######
    #  Traffice Policy at Ingress ath xx.  #
    ########################################
    echo "Uplink => ingress qdisc"
    tc qdisc add dev $IFACE handle ffff: ingress
    #tc filter add dev $IFACE prio 99 protocol ip handle fff: u32 divisor 256
    #tc filter add dev $IFACE parent ffff: protocol ip prio 99 u32 fh fff: ht divisor 256
    echo "Uplink => filter u32"
    tc filter add dev $IFACE parent ffff:0 prio 99 protocol ip u32
    echo "Uplink => filter hashtable[256]"
    tc filter add dev $IFACE parent ffff:0 prio 99 protocol ip handle 500: u32 divisor 256
    echo "Uplink => filter link to hashtable"
    tc filter add dev $IFACE parent ffff: prio 1 protocol ip u32 \
                    match ip src 0.0.0.0/0 \
                    hashkey mask 0xffffffff at 12 \
                    link 500:

    echo "Uplink => filter bucket -> policy"
    for i in $(seq 0 255); do
    #    echo ${i}
        tc filter add dev $IFACE parent ffff: prio 99 protocol ip u32 \
                      ht 500: sample u32 `printf "0x%08x" $i` 0x000000ff at 12 \
                      match ip src 0.0.0.0/0 \
                      police rate ${UPLOAD}bit burst 15k drop flowid :1
    done

    ######## Downlink limit for clients ######
    #        Hierachical Token Bucket.       #
    ##########################################
    echo "Downlink <= root"
    tc qdisc add dev $IFACE root handle 1: htb default 1
    echo "Downlink <= class htb"
    tc class add dev $IFACE parent 1: classid 1:1000 htb rate 1000mbit burst 15k

    echo "Downlink <= subclass"
    for i in $(seq 0 255); do
        tc class add dev $IFACE parent 1:1000 classid 1:`printf "%x" $((1+$i))` htb rate ${DOWNLOAD}bit burst 15k
    done

    echo "Downlink <= filter u32"
    tc filter add dev $IFACE parent 1: prio 50 protocol ip u32
    echo "Downlink <= filter hashtable[256]"
    tc filter add dev $IFACE parent 1: prio 50 protocol ip handle 100: u32 divisor 256
    echo "Downlink <= filter link to hashtable"
    tc filter add dev $IFACE parent 1: prio 5 protocol ip u32 \
                    match ip src 0.0.0.0/0 \
                    hashkey mask 0xffffffff at 12 \
                    link 100:

    echo "Downlink <= filter bucket -> policy"
    for i in $(seq 0 255); do
        tc filter add dev $IFACE parent 1: prio 50 protocol ip u32 \
                      ht 100: sample u32 `printf "0x%08x" $i` 0x000000ff at 12 \
                      match ip src 0.0.0.0/0 flowid 1:`printf "%x" $((1+$i))`
    done

    exit
fi




echo "Well done!"
