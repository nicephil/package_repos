#!/bin/sh


function handle_ddns()
{
    local ops="$1"
    local json_data="$2"
    local section=""
    local lucihelper="/usr/lib/ddns/dynamic_dns_lucihelper.sh"
    json_init
    json_load "$json_data"
    json_get_vars section
    pid=$(cat /var/run/ddns/"$section".pid 2>/dev/null)
    kill -6 $pid 2>/dev/null
    ubus call uci delete "{\"config\":\"ddns\",\"section\":\"$section\"}" 2>/dev/null
    case ops in
        "3") # testing
            ubus call uci set "$json_data"
            $lucihelper -S "$section" -- start
            sleep 5
            pid=$(cat /var/run/ddns/"$section".pid 2>/dev/null)
            [ -z "$pid" ] && {
                return 1
            }
            uptime=$(cat /var/run/ddns/"$section".update)
            [ -z "$uptime" ] && {
                return 1
            }
            ubus call uci revert "{\"config\":\"ddns\"}"
            $lucihelper -S "$section" -- start
            ;;
        "4") # config
            ubus call uci set "$json_data"
            ubus call uci commit "{\"config\":\"ddns\"}"
            ;;
        "5") # delete
            ;;
    esac

    return 0
}


. /usr/share/libubox/jshn.sh
. /lib/functions.sh
. /lib/ramips.sh

json_data="$1"
json_init
json_load "$json_data"
logger -t 'router_config' "$json_data"

operate_type=""
data=""
json_get_vars operate_type data
errcode="0"

case "$operate_type" in
    "3"|"4"|"5")
        handle_ddns "$operate_type" "$data"
        ;;
    *)
        echo "unknown type"
        ;;
esac





return 0
