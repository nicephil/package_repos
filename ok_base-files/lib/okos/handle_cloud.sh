#!/bin/sh

# 1. include scripts
. /lib/functions.sh
. /usr/share/libubox/jshn.sh
. /lib/ar71xx.sh
. /lib/functions/network.sh

# 2. fetch device info
config_load "productinfo"
config_get _mac "productinfo" "mac"
config_get _swversion "productinfo" "swversion"
config_get _production "productinfo" "production"

# 3. assemble json
json_init
json_add_string "version" "$_swversion"
json_add_string "device" "$_mac"
json_add_string "device_type" "$_production"

json_data=$(json_dump)

echo "===>$json_data" | logger -t 'handle_cloud'

# 4. query which oakmgr
SALT="Nobody knows"
KEY="$(echo -n "${SALT}${_mac}" | md5sum | awk '{print $1}')"
PORT="80"
ADDR="api.oakridge.io"
OAKMGR_PUB=""
GW_OK="1"
CAPWAP_FAILURE_COUNT=0

(sleep 20;echo "oakos is up, version:${_swversion}" | logger -p user.info -t '01-SYSTEM-LOG')&

while :
do
    URL="http://${ADDR}:${PORT}/redirector/v1/device/register/?key=${KEY}"
    echo "aa>" "$json_data" $URL |  logger -t 'handle_cloud'
    response=$(curl -q -m 10 -s -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL 2>/dev/ttyS0)
    echo "----->$response" | logger -t 'handle_cloud'

    # renew if gw is unreachable
    [ "$GW_OK" = "0" -a -f "/tmp/firstboot_report" ]  && {
        echo "----->looks gateway is unreachable, renew ip now" | logger -t 'handle_cloud'
        #ubus call network.interface notify_proto '{"action": 2, "interface": "lan1", "signal": 16}'
        /etc/init.d/network restart
        sleep 20
        GW_OK="1"
    }
    network_get_gateway __aa lan1;
    if [ "$__aa" = "0.0.0.0" ]
    then
        GW_OK="0"
    else
        ping -w 3 -c 3 "$__aa" > /dev/null 2>&1
        [ "$?" != "0" ] && GW_OK="0"
    fi

    if [ -f "/tmp/capwapc_run" ]
    then
        CAPWAP_FAILURE_COUNT=0
    else
        CAPWAP_FAILURE_COUNT=$((CAPWAP_FAILURE_COUNT+1))
        if [ $CAPWAP_FAILURE_COUNT -gt 7 ]
        then
            echo "----->capwapc long time no connected, try to restart it now" | logger -t 'handle_cloud'
            /etc/init.d/capwapc restart
            CAPWAP_FAILURE_COUNT=0
        fi
    fi

    if [ -z "$response" ]
    then
        echo "response is null" | logger -t 'handle_cloud'
        sleep 5
        continue
    fi

    json_init
    json_load "$response"
    json_get_var _device "device"
    json_get_var _oakmgr_pub_name "oakmgr_pub_name"
    json_get_var _oakmgr_pub_port "oakmgr_pub_port"

    if [ -z "$_oakmgr_pub_name" ]
    then
        echo "no valid oakmgr_pub_name, so query agian" | logger -p user.info -t 'handle_cloud'
        sleep 5
        continue
    elif [ "$_oakmgr_pub_name" = "$(uci get capwapc.server.mas_server 2>/dev/null)" ]
    then
        echo "existing oakmgr_pub_name:$_oakmgr_pub_name is the same as quried, so no action" | logger -p user.info -t 'handle_cloud'
        sleep 120
        continue
    fi

    echo "_oakmgr_pub_name:$_oakmgr_pub_name, capwapc.mas_server=$(uci get capwapc.server.mas_server 2>/dev/null)" | logger -t 'handle_cloud'
    echo "reboot by handle_cloud, as oakmgr changed!!" | logger -p user.info -t '01-SYSTEM-LOG'
    sleep 60
    reboot -f
done


