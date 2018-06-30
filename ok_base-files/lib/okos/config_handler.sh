#!/bin/sh

DEBUG="$1"
[ -n "$DEBUG" ] && {
    # cpumem info
    #export 'json_data={"data":"{\"cpu_memory\":1}","operate_type":10001}'
    # channel scanning
    #export 'json_data={"data":"{\"radio\":-1}","operate_type":15}'
    #export 'json_data={"data":"{\"server\":\"192.168.254.191\",\"port\":\"1812\",\"username\":\"steve\",\"password\":\"testing\",\"key\":\"testing123\"}","operate_type":18}'
    export 'json_data={"data":"{\"server\":\"192.168.254.183\",\"port\":\"1812\",\"username\":\"leilei.wang\",\"password\":\"Oakridge2016!\",\"key\":\"oakridge\"}","operate_type":18}' 
    # config channel
    # export 'json_data={"data":"{\"r24_channel\":1,\"r5_channel\":149}","operate_type":17}'
}

config_log()
{
    if [ -n "$DEBUG" ]
    then
        echo "new_config: $@"
    else
        logger -p 7 -t 'new_config' $@
    fi
}

. /usr/share/libubox/jshn.sh
. /lib/functions.sh

# json_data env
json_init
json_load "$json_data"

operate_type=""
data=""
json_get_vars operate_type data

#config_log "$cookie" "$operate_type" "$data"

handle_devstats()
{
    local ops="$1"
    local json_data="$2"
    local ret=""

    json_init
    json_load "$json_data"
    json_get_vars cpu_memory

    if [ "$cpu_memory" = "1" ]
    then
        has_cpumemjson=1 has_cookie=$cookie /lib/okos/devstats.sh
    fi
    return 0
}

doing_chscanning()
{
    radio="$1"
    disabled=$(uci get wireless.wifi$radio.disabled)

    # 1. check icm process exists or not
    if [ -z "$(pgrep -f "icm -r $radio")" -a -z "$(pgrep 'restartservices.sh')" ]
    then
        # check disabled wifi
        if [ "$disabled" = "1" ]
        then
            uci set wireless.wifi$radio.disabled=0
            uci commit wireless
            wifi up wifi$radio
            sleep 1
        fi

        (icm -r $radio -i /tmp/icmseldebug_$radio.csv 2>&1 | logger -t 'devstats';has_chscanningjson=1 has_cookie=$cookie /lib/okos/devstats.sh "$radio" "$disabled")&
    fi

    [ -f "/tmp/restartservices.lock" ] && ret="1"

    return $ret
}

handle_chscanning()
{
    local ops="$1"
    local json_data="$2"
    local ret="0"

    if [ -n "$json_data" ]
    then
        json_init
        json_load "$json_data"
        json_get_vars radio
    fi

    if [ -z "$radio" ]
    then
        radio = "-1"
    fi

    if [ "$radio" = "-1" ]
    then
        doing_chscanning 1
        ret=$?
        doing_chscanning 0
        ret=$?
    else
        doing_chscanning $radio
        ret=$?
    fi

    return $ret
}

 handle_setchan()
{
    local ops="$1"
    local json_data="$2"
    local ret=""

    json_init
    json_load "$json_data"
    json_get_vars r24_channel r5_channel

    iw_tmp="$(iwconfig 2>&1 | awk '/ath/{print $1}')"
    ath0=$(echo "$iw_tmp" | awk '/ath50/{print $1;exit}')
    ath1=$(echo "$iw_tmp" | awk '/ath60/{print $1;exit}')

    [ -n "$ath0" -a -n "$r24_channel" ] && iwconfig "$ath0" channel "$r24_channel"
    [ -n "$ath1" -a -n "$r5_channel" ] && iwconfig "$ath1" channel "$r5_channel"

    return 0
}

handle_radtest()
{
    local ops="$1"
    local json_data="$2"
    local ret=""

    json_init
    json_load "$json_data"
    json_get_vars server port username password key

    has_radtestjson=1 has_cookie=$cookie server=$server port=$port username=$username password=$password radkey=$key /lib/okos/devstats.sh 

    return 0
}

case "$operate_type" in
    "10001")
        if ! handle_devstats "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        #config_log "$operate_type $data success"
        return 0
        ;;

    "15")
        if ! handle_chscanning "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;

    "17")
        if ! handle_setchan "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;

    "18")
        if ! handle_radtest "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;

    *)
        config_log "unknown type $operate_type $data"
        return 1
        ;;
esac

return 0
