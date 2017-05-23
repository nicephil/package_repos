#!/bin/sh

mac=$1
tx_rate_limit=$2
rx_rate_limit=$3

# 1. get the ssid QoS weight
qos_weight=1

# 2. set the right limit
/lib/okos/ratelimit_new.sh add $mac $qos_weight ${tx_rate_limit}kbit ${rx_rate_limit}kbit



