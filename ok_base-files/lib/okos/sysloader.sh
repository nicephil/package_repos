#!/bin/sh

# 1. include scripts
. /lib/functions.sh
. /usr/share/libubox/jshn.sh
. /lib/ar71xx.sh
. /lib/okos/sysloader_devstats.sh

# 2. fetch device info
config_load "productinfo"
config_get _mac "productinfo" "mac"
config_get _swversion "productinfo" "bootversion"
config_get _production "productinfo" "production"
config_get _model "productinfo" "model"
config_get _sn "productinfo" "serial"
_ip=$(ifconfig br-lan1 | awk -F'[ :]+' '/inet addr/{print $4}')
_mask=$(ifconfig br-lan1 | awk -F':' '/Mask/{print $4}')
_vendor=${_model%%_*}

# 3. assemble json
json_init
json_add_string "version" "$_swversion"
json_add_string "device" "$_mac"
json_add_string "device_type" "$_production"
json_add_string "private_ip" "$_ip"
json_add_string "private_mask" "$_mask"
json_add_string "manufacturer" "$_vendor"
json_add_string "sn" "$_sn"

json_data=$(json_dump)


# 4. query okos info or which oakmgr
SALT="Nobody knows"
KEY="$(echo -n "${SALT}${_mac}" | md5sum | awk '{print $1}')"
DEFAULT_PORT="80"
PORT="$DEFAULT_PORT"
DEFAULT_ADDR="api.oakridge.io"
SAVED_ADDR=$(uci get capwapc.image.oakmgr_pub_name 2>/dev/null)
if [ -z "$SAVED_ADDR" -o "$SAVED_ADDR" = "0.0.0.0"  ]
then
    ADDR="$DEFAULT_ADDR"
else
    ADDR="$SAVED_ADDR"
fi
ADDR="$DEFAULT_ADDR"
OKOS_MD5SUM=""
IMAGE_URL=""
BOOT_DELAY=""
RETRY_COUNT=0
DOWNLOAD_RETRY_COUNT=0

echo "boot up, local firmware:$_swversion, ip:$_ip" | logger -p user.info -t '01-SYSTEM-LOG'

while :
do
    _server_ip=$(host -W 5 -4 $ADDR | awk '/'"$ADDR"'/{print $4;exit}') 
    [ -z "$_server_ip" -o "$_server_ip" = "found:" ] && _server_ip=$ADDR
    URL="http://${_server_ip}:${PORT}/redirector/v1/device/register/?key=${KEY}"
    echo "local firmware:$_swversion, ip:$_ip" | logger -p user.info -t '01-SYSTEM-LOG'
    echo "connecting to redirector @$_server_ip:$PORT" |  logger -p user.info -t '01-SYSTEM-LOG'
    response=$(curl -q -m 10 -s -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL 2>/dev/ttyS0)
    echo "----->$response" | logger -t 'sysloader'

    # no response, so try query again
    if [ -z "$response" ]
    then
        echo "failed to connect to redirector @$_server_ip:$PORT, err:no response" | logger -p user.err -t '01-SYSTEM-LOG'
        sleep 5
        ADDR="$DEFAULT_ADDR"
        PORT="$DEFAULT_PORT"
        if [ "$RETRY_COUNT" -lt 2 ]
        then
            RETRY_COUNT=$((RETRY_COUNT+1))
            continue
        else
            _okos_md5sum=$(uci get capwapc.image.okos_md5sum 2>/dev/null)
            _image_url=$(uci get capwapc.image.image_url 2>/dev/null)
            _boot_delay=$(uci get capwapc.image.boot_delay 2>/dev/null)
            _device=$(uci get capwapc.image.device 2>/dev/null)
            _oakmgr_pub_name=$(uci get capwapc.image.oakmgr_pub_name 2>/dev/null)
            _oakmgr_pub_port=$(uci get capwapc.image.oakmgr_pub_port 2>/dev/null)
            if [ -n "$_okos_md5sum" -a -n "$_image_url" -a -n "$_oakmgr_pub_name" ]
            then
                response="{'okos_md5sum':'$_okos_md5sum', 'image_url':'$_image_url', 'boot_delay':'$_boot_delay', 'device':'$_device', 'oakmgr_pub_name':'$_oakmgr_pub_name', 'oakmgr_pub_port':'$_oakmgr_pub_port'}"
                echo "no response from redirector, so use local saved oakmgr and image url to continue" | logger -p user.info -t '01-SYSTEM-LOG'
                RETRY_COUNT=0
            else
                RETRY_COUNT=0
                continue
            fi
        fi
    fi
    RETRY_COUNT=0

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

    # no okos info, so try again
    if [ -z "$OKOS_MD5SUM" -o -z "$IMAGE_URL" ]
    then
        echo "failed to connect to redirector @$_server_ip:$PROT, err:no oakos info" | logger -p user.err -t '01-SYSTEM-LOG'
        sleep 5
        report_status "100" "no okos info"
        continue
    fi

    # save info to local
    uci set capwapc.server.mas_server="$_oakmgr_pub_name"
    uci set capwapc.image=image
    uci set capwapc.image.okos_md5sum="$_okos_md5sum"
    uci set capwapc.image.image_url="$_image_url"
    uci set capwapc.image.boot_delay="$_boot_delay"
    uci set capwapc.image.device="$_device"
    uci set capwapc.image.oakmgr_pub_name="$_oakmgr_pub_name"
    uci set capwapc.image.oakmgr_pub_port="$_oakmgr_pub_port"
    uci commit capwapc

    # check the local image verion and queried image version
    _image_server_ip=$(host -W 5 -4 $_oakmgr_pub_name | awk '/'"$_oakmgr_pub_name"'/{print $4;exit}') 
    [ -z "$_image_server_ip" ] && _image_server_ip=$_oakmgr_pub_name
    _image_file=${IMAGE_URL##*/}
    _ver_var=${_image_file%%_*}

    # local the same, so boot local okos
    if [ "$_ver_var" = "$(cat /etc/issue)" ]
    then
        break
    fi

    # 5. download image from image url
    echo "start to download oakos from ${_image_server_ip}, $_ver_var" | logger -p user.info -t '01-SYSTEM-LOG'
    report_status "101" "normal"

    OKOS_FILE="/tmp/okos.gz"
    FILE_MD5SUM=""
    CACHE_FILE="/root/${IMAGE_URL##*/}"

    if [ -f "${CACHE_FILE}" ]
    then
        cp "${CACHE_FILE}" "${OKOS_FILE}"
        cp "${CACHE_FILE}.aria2" "${OKOS_FILE}.aria2"
        echo "-->download resume mode" | logger -t 'sysloader'
    else
        echo "-->download nornmal mode" | logger -t 'sysloader'
    	if [ -n "`ls /root`" ]
    	then
    	    rm -rf /root/*
    	fi
    	echo "${IMAGE_URL}" > /root/imgurl
    fi
    # possibles urls
    _image_server_uri=${IMAGE_URL#http://*/}
    main_image_server_url="http://${_oakmgr_pub_name}/${_image_server_uri}"
    second_image_server_url="http://image.oakridge.vip/${_image_server_uri} http://image.oakridge.io/${_image_server_uri}"
    echo ${_oakmgr_pub_name} | grep  "\.io" > /dev/null 2>&1
    [ "$?" == "0" ] && second_image_server_url="http://image.oakridge.io/${_image_server_uri} http://image.oakridge.vip/${_image_server_uri}"
    other_image_server_urls="$second_image_server_url  http://alpha1.oakridge.vip/${_image_server_uri} http://alpha1.oakridge.io/${_image_server_uri} http://beta2.oakridge.vip/${_image_server_uri} http://beta2.oakridge.io/${_image_server_uri} http://nms1.oakridge.vip/${_image_server_uri} http://nms1.oakridge.io/${_image_server_uri} http://beta1.oakridge.vip/${_image_server_uri} http://beta1.oakridge.io/${_image_server_uri}"
    echo "$_image_server_uri"
    aria2c -t 30 -x 5 --min-split-size=2M --file-allocation=none -c  "$main_image_server_url" "$IMAGE_URL" $other_image_server_urls -d "/" -o ${OKOS_FILE} 2>&1 | logger -t 'sysloader'
    # no file download, so try again
    if [ ! -f "${OKOS_FILE}" ]
    then
        echo "failed to download oakos, err:aria2c failed" | logger -p user.err -t '01-SYSTEM-LOG'
        sleep 5
        report_status "100" "download failed"
        if [ "$DOWNLOAD_RETRY_COUNT" -lt 2 ]
        then
            DOWNLOAD_RETRY_COUNT=$((DOWNLOAD_RETRY_COUNT+1))
            continue
        else
            if [ "$(uci get system.survive_mode.survive_mode 2>/dev/null)" = "1" ]
            then
                echo "***Enter Escape Mode***"
                echo "***Enter Escape Mode***" | logger -p user.info -t '01-SYSTEM-LOG'
                break
            else
                echo "***Not Set Escape Mode***"
                echo "***Not Set Escape Mode***" | logger -p user.info -t '01-SYSTEM-LOG'
                DOWNLOAD_RETRY_COUNT=0
            fi
        fi
    fi

    FILE_MD5SUM="$(md5sum /tmp/okos.gz | awk '{print $1}' 2>/dev/null)"
    # file md5 incorrect, so try again
    if [ "$FILE_MD5SUM" != "$OKOS_MD5SUM" ]
    then
        echo "failed to download oakos, err:md5sum wrong" | logger -p user.err -t '01-SYSTEM-LOG'
        rm -rf /root/*
        rm -rf "${OKOS_FILE}" "${OKOS_FILE}".aria2
        sleep 5
        report_status "100" "image checksum failed"
        if [ "$DOWNLOAD_RETRY_COUNT" -lt 4 ]
        then
            DOWNLOAD_RETRY_COUNT=$((DOWNLOAD_RETRY_COUNT+1))
            continue
        else
            if [ "$(uci get system.survive_mode.survive_mode 2>/dev/null)" = "1" ]
            then
                echo "***Enter Escape Mode***"
                echo "***Enter Escape Mode***" | logger -p user.info -t '01-SYSTEM-LOG'
                break
            else
                echo "***Not Set Escape Mode***"
                echo "***Not Set Escape Mode***" | logger -p user.info -t '01-SYSTEM-LOG'
                DOWNLOAD_RETRY_COUNT=0
            fi
        fi
    fi

    # stop services to free memory
    wifi unload
    /lib/okos/stopservices.sh
    cp /etc/config/wireless_bak /etc/config/wireless

    # 6. loading okos to memory
    echo "local firmware:$_swversion, ip:$_ip" | logger -p user.info -t '01-SYSTEM-LOG'
    echo "connected to redirector @$_server_ip:$PORT" |  logger -p user.info -t '01-SYSTEM-LOG'
    echo "start to download oakos from ${_image_server_ip}, $_ver_var" | logger -p user.info -t '01-SYSTEM-LOG'
    _img_file_size=`stat -c %s ${OKOS_FILE}  |awk -v OFS=',' '{printf("%03d,%03d,%03d\n", (($0-$0%1000000)/1000000)%1000,(($0-$0%1000)/1000)%1000,$0%1000)}'`
    echo "oakos downloaded, ${_img_file_size}bytes" | logger -p user.info -t '01-SYSTEM-LOG'
    report_status "102" "normal"
    [ -n "${BOOT_DELAY}" ] && sleep ${BOOT_DELAY}
    echo "starting oakos" | logger -p user.info -t '01-SYSTEM-LOG'
    kexec -d --command-line="$(cat /proc/cmdline | sed 's/crashkernel=10M@20M//g')" -l ${OKOS_FILE}
    # kexec load failure, so try again
    if [ "$?" != 0 ]
    then
        echo "oakos failed to start, err:oakos memory loaded failed" | logger -p user.err -t '01-SYSTEM-LOG'
        sleep 5
        report_status "100" "kexec load error"
        continue
    fi
    sync
    sleep 1


    # 7. jump to okos entry
    /etc/init.d/network stop
    [ -n "${BOOT_DELAY}" ] && sleep ${BOOT_DELAY}
    kexec -d -e
    # kexec execute failure, so try again
    if [ "$?" != 0 ]
    then
        echo "oakos failed to start, err:oakos executed failed" | logger -p user.err -t '01-SYSTEM-LOG'
        sleep 5
        report_status "100" "kexec execute error"
        /etc/init.d/network restart
        continue
    fi
    sync
    sleep 5
done


# start services in local okos
cp /etc/config/wireless_bak /etc/config/wireless
cp /lib/okos/init.d/* /etc/init.d/.
/etc/init.d/handle_cloud restart
/etc/init.d/supervisor restart
/etc/init.d/capwapc restart
/lib/okos/restartservices.sh debug
