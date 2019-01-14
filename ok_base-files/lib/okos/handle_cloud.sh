#!/bin/sh

# 1. include scripts
. /lib/functions.sh
. /usr/share/libubox/jshn.sh
. /lib/ar71xx.sh
. /lib/functions/network.sh

rand()
{
    min=$1
    max=$(($2-$min+1))
    num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
    echo $(($num%$max+$min))
}

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
DEFAULT_ADDR="api.oakridge.io"
SAVED_ADDR=$(uci get capwapc.image.oakmgr_pub_name 2>/dev/null)
if [ -z "$SAVED_ADDR" -o "$SAVED_ADDR" = "0.0.0.0"  ]
then
    ADDR="$DEFAULT_ADDR"
else
    ADDR="$SAVED_ADDR"
fi
ADDR="$DEFAULT_ADDR"
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
        #/etc/init.d/network restart
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
        echo "redirector/SDC response is null" | logger -t 'handle_cloud'
        sleep 5
        continue
    fi

    json_init
    json_load "$response"
    json_get_var _okos_md5sum "okos_md5sum"
    json_get_var _image_url "image_url"
    json_get_var _boot_delay "boot_delay"
    json_get_var _device "device"
    json_get_var _oakmgr_pub_name "oakmgr_pub_name"
    json_get_var _oakmgr_pub_port "oakmgr_pub_port"

    # get queried version
    _image_file=${_image_url##*/}
    _ver_var=${_image_file%%_*}

    echo "_oakmgr_pub_name:$_oakmgr_pub_name, capwapc.mas_server=$(uci get capwapc.server.mas_server 2>/dev/null), quried_version:$_ver_var, local_version:$(cat /etc/issue)" | logger -t 'handle_cloud'

    if [ -z "$_oakmgr_pub_name" -o -z "$_ver_var" ]
    then
        echo "no valid oakmgr_pub_name, so query agian" | logger -p user.info -t 'handle_cloud'
        if [ -n "$_oakmgr_pub_name" ] 
        then
            ADDR="$_oakmgr_pub_name"
        else
            ADDR="$DEFAULT_ADDR"
        fi
        sleep 5
        continue
    elif [ "$_oakmgr_pub_name" = "$(uci get capwapc.server.mas_server 2>/dev/null)" -a "$_ver_var" = "$(cat /etc/issue)" ]
    then
        echo "existing oakmgr_pub_name:$_oakmgr_pub_name _ver_var:$_ver_var is the same as quried, so no action" | logger -p user.info -t 'handle_cloud'
        sleep 120
        continue
    fi

    timeout=$(rand 1 1200)
    echo "will be reboot by handle_cloud after ${timeout}s, as oakmgr/oakos version changed!!" | logger -p user.info -t '01-SYSTEM-LOG'
    sleep 30
    sleep $timeout
    reboot -f
done


