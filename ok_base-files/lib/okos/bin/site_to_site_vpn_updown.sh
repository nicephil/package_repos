#!/bin/sh

###############################################
# import parameters:
#
# PLUTO_PEER_PORT=0
# PLUTO_MARK_OUT=101/0xffffffff
# SHLVL=2
# PLUTO_REQID=1
# PLUTO_PEER_CLIENT=0.0.0.0/0
# PLUTO_UNIQUEID=3
# PLUTO_PEER=68.121.161.25
# PLUTO_ME=192.168.1.168
# PLUTO_MY_PROTOCOL=0
# PLUTO_PEER_ID=68.121.161.25
# PLUTO_VERB={up-client|down-client}
# PLUTO_INTERFACE=eth0
# PLUTO_UDP_ENC=4500
# PATH=/usr/sbin:/usr/bin:/sbin:/bin
# PLUTO_MARK_IN=101/0xffffffff
# PLUTO_MY_PORT=0
# PLUTO_VERSION=1.1
# PLUTO_MY_CLIENT=0.0.0.0/0
# PLUTO_PEER_PROTOCOL=0
# PWD=/
# PLUTO_CONNECTION=s_101-t_101
# PLUTO_MY_ID=223.93.139.132
# PLUTO_PROTO=esp

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
elif [ "$PLUTO_VERB" = 'down-client' ]; then
    for remote_subnet in ${remote_subnets//,/ }; do
        echo "ip route del ${remote_subnet} dev ${tunnel_name} scope link"
        ip route del ${remote_subnet} dev ${tunnel_name} scope link
    done
    echo "ip tunnel del ${tunnel_name}"
    ip tunnel del ${tunnel_name}
fi

echo "$PLUTO_VERB is done."

