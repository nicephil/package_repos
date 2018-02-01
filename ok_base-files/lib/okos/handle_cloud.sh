#!/bin/sh

# 1. include scripts
. /lib/functions.sh
. /usr/share/libubox/jshn.sh

# 2. fetch device info
config_load "productinfo"
config_get _mac "productinfo" "mac"
config_get _bootversion "productinfo" "bootversion"
config_get _production "productinfo" "production"

# 3. assemble json
json_init
json_add_string "version" "$_bootversion"
json_add_string "device" "$_mac"
json_add_string "device_type" "$_production"

json_data=$(json_dump)

echo "===>$json_data" | logger -t 'handle_cloud'

# 4. query okos info or which oakmgr
SALT="Nobody knows"
KEY="$(echo -n "${SALT}${_mac}" | md5sum | awk '{print $1}')"
DEFAULT_PORT="80"
PORT="$DEFAULT_PORT"
DEFAULT_ADDR="api.oakridge.io"
ADDR="$DEFAULT_ADDR"
OKOS_MD5SUM=""
IMAGE_URL=""
BOOT_DELAY=""

while :
do
    URL="http://${ADDR}:${PORT}/redirector/v1/device/register/?key=${KEY}"
    echo "$json_data" $URL |  logger -t 'handle_cloud'
    response=$(curl -q -m 10 -s -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL 2>/dev/ttyS0)
    echo "----->$response" | logger -t 'handle_cloud'

    # no response, so try query again
    if [ -z "$response" ]
    then
        echo "response is invalid, try again" | logger -t 'handle_cloud'
        sleep 5
        ADDR="$DEFAULT_ADDR"
        PORT="$DEFAULT_PORT"
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

    OKOS_MD5SUM="$_okos_md5sum"
    IMAGE_URL="$_image_url"
    BOOT_DELAY="$_boot_delay"
    if [ -n "$_oakmgr_pub_name" ]
    then
        ADDR="$_oakmgr_pub_name"
    else
        ADDR="$DEFAULT_ADDR"
        sleep 5
    fi
    if [ -n "$_oakmgr_pub_port" ] 
    then
        PORT="$_oakmgr_pub_port"
    else
        PORT="$DEFAULT_PORT"
        sleep 5
    fi

    uci set capwapc.server.mas_server="$_oakmgr_pub_name"
    uci commit capwapc

    # no okos info, so try again
    if [ -z "$OKOS_MD5SUM" -o -z "$IMAGE_URL" ]
    then
        echo "no okos info, try again" | logger -t 'handle_cloud'
        sleep 5
        report_status "100" "no okos info"
        continue
    fi

    # 5. download image from image url
    echo "--->downloading image from IMAGE_URL:${IMAGE_URL}" | logger -t 'handle_cloud'
    report_status "101" "normal"

    OKOS_FILE="/tmp/okos.gz"
    FILE_MD5SUM=""
    CACHE_FILE="/root/${IMAGE_URL##*/}"

    if [ -f "${CACHE_FILE}" ]
    then
        cp "${CACHE_FILE}" "${OKOS_FILE}"
        cp "${CACHE_FILE}.aria2" "${OKOS_FILE}.aria2"
        echo "-->download resume mode" | logger -t 'handle_cloud'
    else
        echo "-->download nornmal mode" | logger -t 'handle_cloud'
    	if [ -n "`ls /root`" ]
    	then
    	    rm -rf /root/*
    	fi
    	echo "${IMAGE_URL}" > /root/imgurl
    fi
    aria2c -x 5 --min-split-size=2M --file-allocation=none -c  "$IMAGE_URL" -d "/" -o ${OKOS_FILE} 2>&1 | logger -t 'handle_cloud'
    # no file download, so try again
    if [ ! -f "${OKOS_FILE}" ]
    then
        echo "download failed from ${IMAGE_URL}, try again" | logger -t 'handle_cloud'
        sleep 5
        report_status "100" "download failed"
        continue
    fi

    FILE_MD5SUM="$(md5sum /tmp/okos.gz | awk '{print $1}' 2>/dev/null)"
    # file md5 incorrect, so try again
    if [ "$FILE_MD5SUM" != "$OKOS_MD5SUM" ]
    then
        echo "md5sum: ${FILE_MD5SUM}, ${OKOS_MD5SUM}, try again" | logger -t 'handle_cloud'
        rm -rf /root/*
        rm -rf "${OKOS_FILE}" "${OKOS_FILE}".aria2
        sleep 5
        report_status "100" "image checksum failed"
        continue
    fi

    # 6. loading okos to memory
    echo "--->loading ${OKOS_FILE} to memory by kexec -l" | logger -t 'handle_cloud'
    report_status "102" "normal"
    kexec -d --command-line="$(cat /proc/cmdline | sed 's/crashkernel=10M@20M//g')" -l ${OKOS_FILE}
    # kexec load failure, so try again
    if [ "$?" != 0 ]
    then
        echo "kexec load error, try again" | logger -t 'handle_cloud'
        sleep 5
        report_status "100" "kexec load error"
        continue
    fi
    sync
    sleep 1


    # 7. jump to okos entry
    [ -n "${BOOT_DELAY}" ] && sleep ${BOOT_DELAY}
    echo "--->jump to new okos ${OKOS_FILE} by kexec -e" | logger -t 'handle_cloud'

    kexec -d -e
    # kexec execute failure, so try again
    if [ "$?" != 0 ]
    then
        echo "kexec execute error, try again" | logger -t 'handle_cloud'
        sleep 5
        report_status "100" "kexec execute error"
        continue
    fi
    sync
    sleep 5
done
