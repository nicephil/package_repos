#!/bin/sh

# echo $DNSMASQ_REQUESTED_OPTIONS 

mac="$1"
option55="$DNSMASQ_REQUESTED_OPTIONS"

# mac="00:17:f2:d1:a3:32"
# option55="1,33,3,6,15,28,51,58,59,119"

clientdatabase='clientdatabase.oakridge.io:8103'
# clientdatabase='192.168.254.106:8103'

if [ -n $DNSMASQ_REQUESTED_OPTIONS ]; then
    json_data="'{\"clients\":{\"${mac}\":{\"dhcp_fingerprint\":\"${option55}\"}}}'"
    # echo $json_data
    cmd="curl -X POST -H 'Content-Type: application/json' 'http://${clientdatabase}/clientdatabase/v0/client/analyzor?key=1' --data $json_data"
    # echo $cmd
    eval $cmd >/dev/null 2>&1
fi

