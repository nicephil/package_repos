#!/bin/sh

function config_log()
{
    logger -t 'router_config' $@
}

function handle_ddns()
{
    local ops="$1"
    local json_data="$2"
    local section=""
    local name=""
    local lucihelper="/usr/lib/ddns/dynamic_dns_lucihelper.sh"
    local ret=""
    json_init
    json_load "$json_data"
    json_get_vars name
    section=$name
    pid=$(cat /var/run/ddns/"$section".pid 2>/dev/null)
    kill -6 $pid 2>/dev/null
    ubus call uci delete "{\"config\":\"ddns\",\"section\":\"$section\"}" 2>/dev/null
    case "$ops" in
        "3") # testing
            ubus call uci add "$json_data"
            ret="$?"
            $lucihelper -S "$section" -- start
            sleep 5
            pid=$(cat /var/run/ddns/"$section".pid 2>/dev/null)
            uptime=$(cat /var/run/ddns/"$section".update)
            ubus call uci revert "{\"config\":\"ddns\"}" &
            $lucihelper -S "$section" -- start &
            [ -z $pid -o -z $uptime -o "$ret" != "0" ] && return 1
            ;;
        "4") # config
            ubus call uci add "$json_data"
            ret="$?"
            [ "$ret" != "0" ] && return 1
            ubus call uci commit "{\"config\":\"ddns\"}"
            ret="$?"
            [ "$ret" != "0" ] && return 1
            ;;
        "5") # delete
            ubus call uci commit "{\"config\":\"ddns\"}"
            ret="$?"
            [ "$ret" != "0" ] && return 1
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}


. /usr/share/libubox/jshn.sh
. /lib/functions.sh
. /lib/ramips.sh

# json_data env
config_log "$json_data"
json_init
json_load "$json_data"

operate_type=""
data=""
json_get_vars operate_type data

case "$operate_type" in
    "3"|"4"|"5")
        if handle_ddns "$operate_type" "$data"
        then
            return 1
        fi
        ;;
    *)
        echo "unknown type"
        return 1
        ;;
esac

return 0
