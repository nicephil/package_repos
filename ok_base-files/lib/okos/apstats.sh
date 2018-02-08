#!/bin/sh

apstats_trap () {
    logger -t apstats "gets trap"
    lock -u /tmp/.iptables.lock
}
trap 'apstats_trap; exit' INT TERM ABRT QUIT ALRM


# 1. read config
. /lib/functions.sh
config_load productinfo
config_get mac productinfo mac
if [ -z "$mac" ]
then
    echo "mac is wrong"
    return 1
fi
mac=`echo $mac|tr -d ':'`
config_load capwapc
config_get mas_server server mas_server
if [ -z "$mas_server" ]
then
    echo "mas_server is empty"
    return 1
fi
config_load wireless

timestamp=`date +%s`


# $1 - all total uplink
# $2 - all total downlink
fetch_client_stats ()
{
    local all_total_uplink_var="$1"
    local all_total_downlink_var="$2"

    unset "${all_total_uplink_var}"
    unset "${all_total_downlink_var}"
    lock /tmp/.iptables.lock

    local _all_total_uplink=$(iptables -L total_uplink_traf -n -v --line-number -x | awk '/RETURN/{print $3}')
    local _all_total_downlink=$(iptables -L total_downlink_traf -n -v --line-number -x | awk '/RETURN/{print $3}')

    export "${all_total_uplink_var}=$_all_total_uplink"
    export "${all_total_downlink_var}=$_all_total_downlink"

    iptables -Z total_uplink_traf
    iptables -Z total_downlink_traf

    lock -u /tmp/.iptables.lock

    return 0
}

# 4. generate json file
. /usr/share/libubox/jshn.sh
json_init
json_add_string "mac" "`echo ${mac} | sed 's/://g'`"
json_add_int "timestamp" "$timestamp"

# 4.1 Add WLAN
# fetch WLAN Stats
local Delta_txB=""
local Delta_rxB=""

fetch_client_stats Delta_txB Delta_rxB
# echo "+++++>"WLAN", $Delta_txB, $Delta_rxB"

json_add_object "WLAN"
json_add_int "Tx_Data_Bytes" "$Delta_rxB"
json_add_int "Rx_Data_Bytes" "$Delta_txB"
json_close_object


# 4.2 Add VAP
json_add_array "VAP_Stats"
json_close_array

# 8. generate .json
rm -rf /tmp/apstats_*.json
json_file=apstats_${mac}_${timestamp}.json
json_dump 2>/dev/null | tee /tmp/${json_file}


if [ ! -e "/tmp/$json_file" ]
then
    echo "json file wrong"
    return 1
fi

# 10. upload json file to nms
URL="http://${mas_server}/nms/file/device/stat?objectname=${json_file}&override=1"
curl -s -F "action=upload" -F "filename=@/tmp/${json_file}"  "$URL"
