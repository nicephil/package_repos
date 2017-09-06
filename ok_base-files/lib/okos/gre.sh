#!/bin/sh

################################################################################
# README:
#
# To support Ethernet over GRE tunnel on openwrt, you should install items below
# 1) make kernel_menuconfig
#      Networking Support
#        Networking Options
#          IP: GRE demultiplexer
#          IP: GRE tunnels over ip
# 2) make menuconfig (.config)
#      Network
#        gre
#        grev4
#      Kernel Modules
#        Network Support
#        kmod-gre
# 3) opkg update; opkg install ip
#
# Notes:
#     without item #3, you could see all the component exist as well, but if
#     you are trying to create GRE tunnel by `ip link add ... `, you will
#     fail and encounter `ip: RTNETLINK answers: File exists` error hint.
#
# Theory:
#     The basic idea of the design is about to setup a L2vpn network to 
#     distinguish `guest network` defined by us. Since VLAN is too much for 
#     our customer, we chose GRE tunnel here. An ethernet over GRE tunnel will
#     be built up betwenn each pair of AP and gateway to transmit the traffic
#     of `guest network`. To implement this, the ethernet over GRE tunnel will
#     be attached to a bridge on each peer.
#     Then, on AP side, all the interfaces belong to `guest network` will be
#     attached to this special bridge (br-lan4000).
#     On gateway side, all the GRE tunnels connected to each AP will be
#     integrated together in the special bridge with the same name. After this,
#     the L3 bridge inteface (br-lan4000) will behave the role of gateway to 
#     this guest network. Static IP, DHCP & DNS server should be assigned onto
#     it of course, so that all the client and AP attached to this guest 
#     network will acquire IP address from it and send traffic outside of 
#     its direct subnet to it.
#     If the gateway is an AP as well, the local interfaces belong to `guest
#     network` should be introduced into the bridge either.
#
# Tricky part:
#     It's not difficult to setup Ethernet over GRE tunnel between our AP and 
#     gateway (no matter on edge router X or the AP as gateway). The trick is
#     about MTU setting. After added into a bridge for `guest network`, the MTU
#     of the bridge and all the interfaces attached to the bridge will be pulled
#     down to 1462 as the GRE tunnel link. Then, you could not send out any big
#     package over the bridge except you reset the MTU to 1500.
#     To reset MTU to 1500 on ethernet interface,
#     1) if you just `ip link set dev eth0 mtu 1500`, iproute will do nothing
#        since it might think of you don't want to change anything.
#     2) if you change MTU to a smaller value and change it back to 1500 bytes,
#        you have to do this on all the sub-interfaces one by one, since the 
#        change on the master intefaces could not impact sub-interfaces on it.
#     3) you can change MTU to a bigger value and change it back on the master
#        interface, but unfortunately, it will be treated as invalid parameter
#        on openwrt CC version.
################################################################################

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
GW_IFACES=`ifconfig | awk '/eth0.409/{print $1}'`

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
    local link=$1
    local remote_ip=$2
    local name=$3
    local local_ip=$( ifconfig $link | awk '/inet addr:/{print $2}' | cut -d: -f 2 )
    echo "Trying to connect $remote_ip from $local_ip "

    run "ip link add link $link name $name type gretap remote $remote_ip local $local_ip ttl 255"
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

    create_gre $PLAIN_LAN $remote_ip "${PRE_GRE_NAME}${remote_ip}"
}

add_on_ap ()
{
    local remote_ip=$( ip r | awk '/default/{print $3}' )

    create_gre $PLAIN_LAN $remote_ip $GRE_NAME
}


add_on_router ()
{
    local target_ip=$1
    local target_ip_hex=$(ipstr2hex $target_ip)

    local link iface lan_if netmask_shift lan_ip lan_net_hex
    for iface in $GW_IFACES; do
        lan_if=$( ip addr show $iface | awk '/inet /{print $2}' )
        [ -z $lan_if ] && log 7 "$iface is not a L3 i/f with ip assigned." && return 1
        netmask_shift=$(( 32 - $( echo $lan_if | cut -d / -f 2 ) ))
        lan_ip=$( echo $lan_if | cut -d / -f 1 )
        lan_net_hex=$(( $( ipstr2hex $lan_ip ) >> $netmask_shift ))
        if [ $lan_net_hex == $(( $target_ip_hex >> $netmask_shift )) ]; then
            link=$iface
            break
        fi
    done
    [ -z $link ] && log 7 "Can't find out local lan port for GRE tunnel to $target_ip ." &&  return 1
    create_gre $iface $target_ip "${PRE_GRE_NAME}${target_ip_hex}"
}

start_ap ()
{
    brctl show $GUEST_LAN > /dev/null
    [ $? != 0 ] && log 6 "$GUEST_LAN doesn't exist. Load GRE service failed." && exit 1
    log 7 "GRE service start."
}

stop_ap ()
{
    run "brctl delif $GUEST_LAN $GRE_NAME"
    run "ip link del $GRE_NAME type gretap"
    run "ip link set dev $GUEST_LAN mtu 1500"

    log 7 "GRE service stop."
}

start_router ()
{
    brctl show | grep $GUEST_LAN > /dev/null 
    if [ $? != 0 ]; then
        run "brctl addbr $GUEST_LAN"
        run "ip link set dev $GUEST_LAN up"
    fi
    log 7 "GRE service start."
}

stop_router ()
{
    #local tunnels=$( brctl show $GUEST_LAN | sed '1d' | tr '\t ' '\n' | awk '/${PRE_GRE_NAME}/' )
    local tunnels=$( ip link show | awk -v pattern="$PRE_GRE_NAME.*master $GUEST_LAN" '$0 ~ pattern{print $2}' | cut -d@ -f 1 )
    local tnl
    for tnl in $tunnels; do
        run "ip link del $tnl type gretap"
    done
#    run "brctl delbr $GUEST_LAN"

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

