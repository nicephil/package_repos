#!/bin/sh

# 1. include scripts
. /lib/functions.sh
. /usr/share/libubox/jshn.sh
. /lib/ramips.sh

if [ -f "/tmp/.dready" ] 
then
    # 2. fetch device info
    config_load "productinfo"
    config_get _mac "productinfo" "mac"
    config_get _swversion "productinfo" "swversion"

    # 3. assemble json
    json_init
    json_add_string "version" "$_swversion"
    json_add_string "device" "$_mac"

    json_data=$(json_dump)

    echo "===>$json_data"

    # 4. query which oakmgr
    API_KEY="xxxx"
    CLOUD_URL="https://api.oakridge.io/device_register/?key=${API_KEY}"

    response=$(curl -m 10 -s -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $CLOUD_URL 2>/dev/null)

    echo "----->$response"

    json_load "$response"
    json_get_var _version "version"
    json_get_var _device "device"
    json_get_var _oakmgr_pub_name "oakmgr_pub_name"
    json_get_var _oakmgr_pub_port "oakmgr_pub_port"
fi

if [ ! -f "/tmp/latest-okos.gz" ]
then
    b_path=""
    b_name=$(ramips_board_name)
    case "${b_name}" in
        "ubnt-erx")
            b_path="ubnterx"
            ;;
    esac
    wget http://image.oakridge.vip:8000/images/ap/${b_path}/okos/latest-okos.gz -O /tmp/latest-okos.gz
    kexec -d --command-line="$(cat /proc/cmdline)" -l /tmp/latest-okos.gz
    sync
    sleep 1
fi

if [ -f "/tmp/latest-okos.gz" ]
then
    kexec -d -e
fi
