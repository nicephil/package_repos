#!/bin/sh

uci -q batch <<-EOF
    set network.lan.ifname='eth1'
    set network.lan.ipaddr='172.16.254.254'
    set network.wan.ifname='eth0'
EOF
