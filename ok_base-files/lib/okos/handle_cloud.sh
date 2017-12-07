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

while :
do
    URL="http://${ADDR}:${PORT}/redirector/v1/device/register/?key=${KEY}"
    echo curl -vv -m 10 -s -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL |  logger -t 'handle_cloud'
    response=$(curl -m 10 -s -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL 2>/dev/ttyS0)
    echo "----->$response" | logger -t 'handle_cloud'

    if [ -z "$response" ]
    then
        echo "response is null" | logger -t 'handle_cloud'
        sleep 10
        continue
    fi

    json_load "$response"
    json_get_var _device "device"
    json_get_var _oakmgr_pub_name "oakmgr_pub_name"
    json_get_var _oakmgr_pub_port "oakmgr_pub_port"

    if [ -n "$_oakmgr_pub_name" ]
    then
        OAKMGR_PUB="$_oakmgr_pub_name"
        break
    fi

done

# 5. setup the new oakmgr
echo "====> set new oakmgr: $OAKMGR_PUB" | logger -t 'handle_cloud'
uci set capwapc.server.mas_server="$OAKMGR_PUB"; uci commit capwapc;
/etc/init.d/capwapc restart
