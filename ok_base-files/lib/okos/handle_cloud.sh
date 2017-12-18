#!/bin/sh

# 1. include scripts
. /lib/functions.sh
. /usr/share/libubox/jshn.sh

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

# 4. query okos info or which oakmgr
SALT="Nobody knows"
KEY="$(echo -n "${SALT}${_mac}" | md5sum | awk '{print $1}')"
PORT="80"
ADDR="api.oakridge.io"
OKOS_MD5SUM=""
IMAGE_URL=""
BOOT_DELAY=""

while [ -z "$OKOS_MD5SUM" -o -z "$IMAGE_URL" ]
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
    json_get_var _okos_md5sum "okos_md5sum"
    json_get_var _image_url "image_url"
    json_get_var _boot_delay "boot_delay"
    json_get_var _device "device"
    json_get_var _oakmgr_pub_name "oakmgr_pub_name"
    json_get_var _oakmgr_pub_port "oakmgr_pub_port"

    OKOS_MD5SUM="$_okos_md5sum"
    IMAGE_URL="$_image_url"
    BOOT_DELAY="$_boot_delay"
    [ -n "$_oakmgr_pub_name" ] && ADDR="$_oakmgr_pub_name"
    [ -n "$_oakmgr_pub_port" ] && PORT="$_oakmgr_pub_port"
done

# 5. download image from image url
echo "--->downloading image from IMAGE_URL:${IMAGE_URL}" | logger -t 'handle_cloud'

OKOS_FILE="/tmp/okos.gz"
FILE_MD5SUM=""

while [ "$FILE_MD5SUM" != "$OKOS_MD5SUM" ]
do
    wget "$IMAGE_URL" -O ${OKOS_FILE}
    if [ ! -f "${OKOS_FILE}" ]
    then
        echo "download failed from ${IMAGE_URL}" | logger -t 'handle_cloud'
        sleep 10
        continue
    fi

    FILE_MD5SUM="$(md5sum /tmp/okos.gz | awk '{print $1}' 2>/dev/null)"
    echo "md5sum: ${FILE_MD5SUM}, ${OKOS_MD5SUM}" | logger -t 'handle_cloud'
done

# 6. loading okos to memory
echo "--->loading ${OKOS_FILE} to memory by kexec -l" | logger -t 'handle_cloud'
kexec -d --command-line="$(cat /proc/cmdline)" -l ${OKOS_FILE}
sync
sleep 1


# 7. jump to okos entry
[ -n "${BOOT_DELAY}" ] && sleep ${BOOT_DELAY}
echo "--->jump to new okos ${OKOS_FILE} by kexec -e" | logger -t 'handle_cloud'

kexec -d -e
