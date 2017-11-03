#!/bin/sh

. /lib/functions.sh
. /lib/functions/network.sh

# 1. get mac and timestamp
config_load capwapc
config_get mas_server "server" "mas_server"
timestamp="`date +%s`"

config_load productinfo
config_get mac "productinfo" "mac"
mac="$(echo "$mac" | tr -d ":")"


# 2. generate json file
. /usr/share/libubox/jshn.sh
. /lib/okos/trafstats.sh

enable_interface_stats

fetch_interface_stats _interfaces_stats

json_init


json_add_string "mac" "${mac}"
json_add_int "timestamp" "${timestamp}"

json_add_array "INTERFACE_STAT"
for iface_stats in $_interfaces_stats
do

    OIFS=$IFS;IFS='_';set -- $iface_stats;__iface=$1;__uplink=$2;__downlink=$3;IFS=$OIFS
    network_get_lname _iface_lname  "${__iface}"
    json_add_string "name" "${_iface_lname}"
    json_add_int "Tx_Data_Bytes" "$__uplink"
    json_add_int "Rx_Data_Bytes" "$__downlink"
done
json_close_array

# 8. generate .json
rm -rf /tmp/apstats_${mac}_*.json
json_file="apstats_${mac}_${timestamp}.json"
json_dump 2>/dev/null | tee /tmp/${json_file}


if [ ! -e "/tmp/$json_file" ]
then
    exit
fi

# 10. upload json file to nms
URL="http://${mas_server}/nms/file/device/stat?objectname=${json_file}&override=1"
curl -s -F "action=upload" -F "filename=@/tmp/${json_file}"  "$URL"
