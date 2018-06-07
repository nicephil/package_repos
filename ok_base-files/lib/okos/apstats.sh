#!/bin/sh

# check if services is restarting
lockfile="/tmp/restartservices.lock"
if [ -f "$lockfile" ]
then
        return 1
fi

if [ -f "/tmp/apstats.lock" ]
then
    return 1
fi

apstats_debug_log () {
    #echo "$@" | logger -p 7 -t apstats
    return
}

apstats_err_log () {
    echo "$@" | logger -p 3 -t apstats
}

apstats_trap () {
    apstats_err_log "gets trap on apstats"
    rm -rf /tmp/apstats.lock
}
trap 'apstats_trap; exit 1' INT TERM ABRT QUIT ALRM


touch /tmp/apstats.lock

apstats_debug_log "$(date) in"

# 1. read config
. /lib/functions.sh
config_load productinfo
config_get mac productinfo mac
if [ -z "$mac" ]
then
    apstats_err_log "mac is wrong"
    rm -rf /tmp/apstats.lock
    return 1
fi
mac=`echo $mac|tr -d ':'`
config_load capwapc
config_get mas_server server mas_server
if [ -z "$mas_server" ]
then
    apstats_err_log "mas_server is empty"
    rm -rf /tmp/apstats.lock
    return 1
fi
config_load wireless

timestamp=`date +%s`

ebtabls_CMD="ebtables"

# $1 - all total uplink
# $2 - all total downlink
fetch_client_stats ()
{
    local all_total_uplink_var="$1"
    local all_total_downlink_var="$2"

    unset "${all_total_uplink_var}"
    unset "${all_total_downlink_var}"

    local _all_total_uplink=$($ebtabls_CMD -L total_uplink_traf --Lc --Lmac2 | awk '/RETURN/{print $NF}')
    local _all_total_downlink=$($ebtabls_CMD -L total_downlink_traf --Lc --Lmac2 | awk '/RETURN/{print $NF}')
    [ -z "$_all_total_uplink" ] && _all_total_uplink=0
    [ -z "$_all_total_downlink" ] && _all_total_downlink=0

    export "${all_total_uplink_var}=$_all_total_uplink"
    export "${all_total_downlink_var}=$_all_total_downlink"

    $ebtabls_CMD -Z total_uplink_traf
    $ebtabls_CMD -Z total_downlink_traf

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
    apstats_err_log "json file wrong"
    rm -rf /tmp/apstats.lock
    return 1
fi

# 10. upload json file to nms
URL="http://${mas_server}/nms/file/device/stat?objectname=${json_file}&override=1"
curl -m 60 -s -F "action=upload" -F "filename=@/tmp/${json_file}"  "$URL"

apstats_debug_log "upload json file done"

rm -rf /tmp/apstats.lock
apstats_debug_log "$(date) out"
