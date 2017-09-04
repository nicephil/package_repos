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
    local cmd="$1"
    echo "$cmd"
    eval "$cmd" 2>&1
}

#GW_IFACES="eth0.4090 eth0.4091 eth0.4092 eth0.4093 eth0.4094"
GW_IFACES=`ifconfig | awk '/eth0.4/{print $1}'`

PLAIN_LAN='br-lan1'
GUEST_LAN='br-lan4000'
GRE_NAME='guest'
PRE_GRE_NAME='ap-'

get_ip ()
{
    local iface=$1
    local ip=$( ifconfig br-lan1 | awk '/inet addr:/{print $2}' | cut -d: -f 2 )
    echo $ip
}

create_gre ()
{
    local local_ip=$1
    local remote_ip=$2
    local name=$3
    echo "Trying to connect $remote_ip from $local_ip "

    run "ip link add $name type gretap remote $remote_ip local $local_ip ttl 255"
    run "ip link set $name up"
    run "brctl addif $GUEST_LAN $name"

    run "ip link set dev eth0 mtu 1600"
}

ipstr2hex ()
{
    local ipstr=$1
    local iphex
    OIFS=$IFS;IFS=.;set -- $ipstr;iphex=$(( ($1*256**3) + ($2*256**2) + ($3*256) + $4 ));IFS=$OIFS;
    echo $iphex
}
iphex2str ()
{
    local iphex=$1
    local ipstr
    echo $ipstr
}

add_on_apgw ()
{
    local remote_ip=$1
    local local_ip=$( get_ip $PLAIN_LAN )

    create_gre $local_ip $remote_ip "${PRE_GRE_NAME}${remote_ip}"
}

add_on_ap ()
{
    local local_ip=$( get_ip $PLAIN_LAN )
    local remote_ip=$( ip r | awk '/default/{print $3}' )

    create_gre $local_ip $remote_ip $GRE_NAME
}


add_on_router ()
{
    local target_ip=$1
    local target_ip_hex=$(ipstr2hex $target_ip)

    local local_ip iface lan_if netmask_shift lan_ip lan_net_hex
    for iface in $GW_IFACES; do
        lan_if=$(ip addr show $iface | awk '/inet /{print $2}')
        netmask_shift=$(( 32 - $( echo $lan_if | cut -d / -f 2 ) ))
        lan_ip=$( echo $lan_if | cut -d / -f 1 )
        lan_net_hex=$(( $( ipstr2hex $lan_ip ) >> $netmask_shift ))
        if [ $lan_net_hex == $(( $target_ip_hex >> $netmask_shift )) ]; then
            local_ip=$lan_ip
            break
        fi
    done
    [ -z $local_ip ] && log 7 "Can't find out local lan port for GRE tunnel to $target_ip ." &&  return 1
    create_gre $local_ip $target_ip "${PRE_GRE_NAME}${target_ip}"
}

start_ap ()
{
    brctl show $GUEST_LAN > /dev/null
    [ $? != 0 ] && log 6 "$GUEST_LAN doesn't exist. Load GRE service failed." && exit 1
    log 7 "GRE service start."
}

stop_ap ()
{
    log 7 "GRE service stop."
}

start_router ()
{
    brctl show | grep $GUEST_LAN > /dev/null 
    [ $? != 0 ] && run "brctl addbr $GUEST_LAN"
    log 7 "GRE service start."
}

stop_router ()
{
    local tunnels=$( brctl show $GUEST_LAN | sed '1d' | tr '\t ' '\n' | awk '/${PRE_GRE_NAME}/' )
    local tnl
    for tnl in $tunnels; do
        run "ip link del $tnl type gretap"
    done
    run "brctl delbr $GUEST_LAN"

    log 7 "GRE service stop."
}

show()
{
    run "ifconfig"
    sleep 1
    run "brctl show"
    sleep 1
    run "ip link show"
    sleep 1
}

