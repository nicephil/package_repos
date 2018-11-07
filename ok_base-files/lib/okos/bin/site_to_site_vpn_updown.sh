#!/bin/sh

###############################################
# import parameters:
#
# export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
# export PLUTO_CONNECTION='s_101-t_101'
# export PLUTO_INTERFACE='eth0'
# export PLUTO_MARK_IN='101/0xffffffff'
# export PLUTO_MARK_OUT='101/0xffffffff'
# export PLUTO_ME='192.168.254.171'
# export PLUTO_MY_CLIENT='0.0.0.0/0'
# export PLUTO_MY_ID='223.93.139.132'
# export PLUTO_MY_PORT='0'
# export PLUTO_MY_PROTOCOL='0'
# export PLUTO_PEER='68.121.161.25'
# export PLUTO_PEER_CLIENT='0.0.0.0/0'
# export PLUTO_PEER_ID='68.121.161.25'
# export PLUTO_PEER_PORT='0'
# export PLUTO_PEER_PROTOCOL='0'
# export PLUTO_PROTO='esp'
# export PLUTO_REQID='1'
# export PLUTO_UDP_ENC='4500'
# export PLUTO_UNIQUEID='1'
# export PLUTO_VERB='up-client'
# export PLUTO_VERSION='1.1'
# export PWD='/'
# export SHLVL='2'

remote_subnets="$1"
remote_ip="$PLUTO_PEER"
local_nat_ip="$PLUTO_ME"
tunnel_name="${PLUTO_CONNECTION##*-}"
id="${PLUTO_CONNECTION##*_}"

if [ "$PLUTO_VERB" = 'up-client' ]; then
    echo "ip tunnel add ${tunnel_name} remote ${remote_ip} local ${local_nat_ip} mode vti key ${id}"
    ip tunnel add ${tunnel_name} remote ${remote_ip} local ${local_nat_ip} mode vti key ${id}
    echo "ip link set ${tunnel_name} up"
    ip link set ${tunnel_name} up
    for remote_subnet in ${remote_subnets//,/ }; do
        echo "ip route add ${remote_subnet} dev ${tunnel_name} scope link"
        ip route add ${remote_subnet} dev ${tunnel_name} scope link
    done
elif [ "$PLUTO_VERB" = 'up-client' ]; then
    for remote_subnet in ${remote_subnets//,/ }; do
        echo "ip route del ${remote_subnet} dev ${tunnel_name} scope link"
        ip route del ${remote_subnet} dev ${tunnel_name} scope link
    done
    echo "ip tunnel del ${tunnel_name}"
    ip tunnel del ${tunnel_name}
fi

echo "$PLUTO_VERB is done."

