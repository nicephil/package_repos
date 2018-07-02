#!/bin/sh

# 1. include scripts
. /lib/functions.sh
. /usr/share/libubox/jshn.sh
. /lib/ar71xx.sh

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
FIRSTBOOT="1"

# 5. setup the new oakmgr
setup_capwapc ()
{
    echo "====> set new oakmgr: $OAKMGR_PUB" | logger -t 'handle_cloud'
    uci set capwapc.server.mas_server="$OAKMGR_PUB"; uci commit capwapc;
    /etc/init.d/capwapc restart
}

(sleep 20;echo "oakos is up, version:${_swversion}" | logger -p user.info -t '01-SYSTEM-LOG')&

while :
do
    URL="http://${ADDR}:${PORT}/redirector/v1/device/register/?key=${KEY}"
    echo "aa>" "$json_data" $URL |  logger -t 'handle_cloud'
    response=$(curl -q -m 10 -s -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL 2>/dev/ttyS0)
    echo "----->$response" | logger -t 'handle_cloud'

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
        #echo "no valid oakmgr_pub_name, so query agian" | logger -p user.info -t '01-SYSTEM-LOG'
        sleep 5
        continue
    elif [ "$_oakmgr_pub_name" = "$(uci get capwapc.server.mas_server 2>/dev/null)" ]
    then
        FIRSTBOOT="0"
        #echo "existing oakmgr_pub_name:$_oakmgr_pub_name is the same as quried, so no action" | logger -p user.info -t '01-SYSTEM-LOG'
        sleep 120
        continue
    fi

    if [ "$FIRSTBOOT" = "1" ]
    then
        OAKMGR_PUB="$_oakmgr_pub_name"
        echo "setup capwapc during firstboot" | logger -t 'handle_cloud'
        setup_capwapc
        FIRSTBOOT="0"
    else
        echo "_oakmgr_pub_name:$_oakmgr_pub_name, capwapc.mas_server=$(uci get capwapc.server.mas_server 2>/dev/null)" | logger -t 'handle_cloud'
        #echo "reboot by handle_cloud!!" | logger -p user.info -t '01-SYSTEM-LOG'
        sleep 60
        reboot -f
    fi

done


