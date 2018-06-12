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
# $3 - all total wan uplink
# $4 - all total wan downlink
fetch_client_stats ()
{
    local all_total_uplink_var="$1"
    local all_total_downlink_var="$2"
    local all_total_wan_uplink_var="$3"
    local all_total_wan_downlink_var="$4"

    unset "${all_total_uplink_var}"
    unset "${all_total_downlink_var}"
    unset "${all_total_wan_uplink_var}"
    unset "${all_total_wan_downlink_var}"

    local _all_total_uplink=$($ebtabls_CMD -L total_uplink_traf --Lc --Lmac2 | awk '/-j RETURN/{print $NF}')
    local _all_total_downlink=$($ebtabls_CMD -L total_downlink_traf --Lc --Lmac2 | awk '/-j RETURN/{print $NF}')
    local _all_total_wan_uplink=$($ebtabls_CMD -L total_wan_uplink_traf --Lc --Lmac2 | awk '/-j RETURN/{print $NF}')
    local _all_total_wan_downlink=$($ebtabls_CMD -L total_wan_downlink_traf --Lc --Lmac2 | awk '/-j RETURN/{print $NF}')
    [ -z "$_all_total_uplink" ] && _all_total_uplink=0
    [ -z "$_all_total_downlink" ] && _all_total_downlink=0
    [ -z "$_all_total_wan_uplink" ] && _all_total_wan_uplink=0
    [ -z "$_all_total_wan_downlink" ] && _all_total_wan_downlink=0

    export "${all_total_uplink_var}=$_all_total_uplink"
    export "${all_total_downlink_var}=$_all_total_downlink"
    export "${all_total_wan_uplink_var}=$_all_total_wan_uplink"
    export "${all_total_wan_downlink_var}=$_all_total_wan_downlink"

    $ebtabls_CMD -Z total_uplink_traf
    $ebtabls_CMD -Z total_downlink_traf
    $ebtabls_CMD -Z total_wan_uplink_traf
    $ebtabls_CMD -Z total_wan_downlink_traf

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
local Delta_wan_txB=""
local Delta_wan_rxB=""

fetch_client_stats Delta_txB Delta_rxB Delta_wan_txB Delta_wan_rxB
# echo "+++++>"WLAN", $Delta_txB, $Delta_rxB $Delta_wan_txB $Delta_wan_rxB"

json_add_object "WLAN"
json_add_int "Tx_Data_Bytes" "$Delta_txB"
json_add_int "Rx_Data_Bytes" "$Delta_rxB"
json_add_int "Tx_Bytes_Wan" "$Delta_wan_txB"
json_add_int "Rx_Bytes_Wan" "$Delta_wan_rxB"
json_close_object


# 4.2 Add VAP
# $1 - ath
# $2 - all total uplink
# $3 - all total downlink
# $4 - all total wan uplink
# $5 - all total wan downlink
fetch_ath_stats ()
{
    local ath="$1"
    local ath_total_uplink_var="$2"
    local ath_total_downlink_var="$3"
    local ath_total_wan_uplink_var="$4"
    local ath_total_wan_downlink_var="$5"

    unset "${ath_total_uplink_var}"
    unset "${ath_total_downlink_var}"
    unset "${ath_total_wan_uplink_var}"
    unset "${ath_total_wan_downlink_var}"

    local _ath_total_uplink=$($ebtabls_CMD -L ath_total_uplink_traf --Lc --Lmac2 | awk '/'"$ath"'/{print $NF}')
    local _ath_total_downlink=$($ebtabls_CMD -L ath_total_downlink_traf --Lc --Lmac2 | awk '/'"$ath"'/{print $NF}')
    local _ath_total_wan_uplink=$($ebtabls_CMD -L ath_total_wan_uplink_traf --Lc --Lmac2 | awk '/'"$ath"'/{print $NF}')
    local _ath_total_wan_downlink=$($ebtabls_CMD -L ath_total_wan_downlink_traf --Lc --Lmac2 | awk '/'"$ath"'/{print $NF}')
    [ -z "$_ath_total_uplink" ] && _ath_total_uplink=0
    [ -z "$_ath_total_downlink" ] && _ath_total_downlink=0
    [ -z "$_ath_total_wan_uplink" ] && _ath_total_wan_uplink=0
    [ -z "$_ath_total_wan_downlink" ] && _ath_total_wan_downlink=0

    export "${ath_total_uplink_var}=$_ath_total_uplink"
    export "${ath_total_downlink_var}=$_ath_total_downlink"
    export "${ath_total_wan_uplink_var}=$_ath_total_wan_uplink"
    export "${ath_total_wan_downlink_var}=$_ath_total_wan_downlink"


    return 0
}


json_add_array "VAP_Stats"
for __ath in $(iwconfig 2>/dev/null | awk '/ath/{print $1}')
do
    [ "$__ath" = "ath50" -o "$__ath" = "ath60" ] && continue
    wifiname=wifi${__ath:3:1}
    vapssid=$(uci get wireless.$__ath.ssid)
    ath_total_uplink_=""
    ath_total_downlink_=""
    ath_total_wan_uplink_=""
    ath_total_wan_downlink_=""
    fetch_ath_stats $__ath ath_total_uplink_ ath_total_downlink_ ath_total_wan_uplink_ ath_total_wan_downlink_
    echo $wifiname $vapssid $__ath $ath_total_uplink_ $ath_total_downlink_ $ath_total_wan_uplink_ $ath_total_wan_downlink_
    json_add_object
    json_add_string "radio" "$wifiname"
    json_add_string "ssid" "$vapssid"
    json_add_int "Tx_Bytes_Wan" "$ath_total_wan_uplink_"
    json_add_int "Rx_Bytes_Wan" "$ath_total_wan_downlink_"
    json_add_int "Tx_Data_Bytes" "$ath_total_uplink_"
    json_add_int "Rx_Data_Bytes" "$ath_total_downlink_"
    json_close_object
done
    $ebtabls_CMD -Z ath_total_uplink_traf
    $ebtabls_CMD -Z ath_total_downlink_traf
    $ebtabls_CMD -Z ath_total_wan_uplink_traf
    $ebtabls_CMD -Z ath_total_wan_downlink_traf
json_close_array


# 4.3 mem_cpu
# $1 - cpu_load
# $2 - mem_load
fetch_cpu_memory()
{
    __cpu_load_name="$1"
    __mem_load_name="$2"
    unset $__cpu_load_name
    unset $__mem_load_name
    kill -9 `pgrep -f "sar -r -u 6 10 -o /tmp/cpu_memory.log"` 2>/dev/null
    __cpu_load=$(sar -u -f /tmp/cpu_memory.log 2>/dev/null | awk '/Average:/{print int(100-$8)}')
    __mem_load=$(sar -r -f /tmp/cpu_memory.log 2>/dev/null | awk '/Average:/{print int($4)}')
    [ -z "$__cpu_load" ] && __cpu_load=20
    [ -z "$__mem_load" ] && __mem_load=70
    export "${__cpu_load_name}=${__cpu_load}"
    export "${__mem_load_name}=${__mem_load}"
    sar -r -u 6 10 -o /tmp/cpu_memory.log > /dev/null 2>&1 &
}

cpu_load_=""
mem_load_=""
fetch_cpu_memory "cpu_load_" "mem_load_"

json_add_object "cpu_memory"
json_add_int "cpu_load" "$cpu_load_"
json_add_int "mem_load" "$mem_load_"
json_close_object


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
