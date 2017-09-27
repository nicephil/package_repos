#!/bin/sh

DEBUG="$1"
[ -n "$DEBUG" ] && {
    export 'json_data={"data":"{\"config\":\"ddns\",\"name\":\"ddns_test\",\"type\":\"service\",\"values\":{\"enabled\":\"1\",\"username\":\"largepuppet\",\"password\":\"wodemima\",\"service_name\":\"3322.org\",\"domain\":\"largepuppet.f3322.net\",\"interface\":\"wan\",\"lookup_host\":\"largepuppet.f3322.net\"}}","operate_type":3}'
}

function config_log()
{
    if [ -n "$DEBUG" ]
    then
        echo "router_config: $@"
    else
        logger -t 'router_config' $@
    fi
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
    config_log "$ops, $section, $json_data"
    kill -6 $pid 2>/dev/null
    pid=$(cat /var/run/ddns/"$section".pid 2>/dev/null)
    kill -6 $pid 2>/dev/null
    rm -rf /var/run/ddns/"$section".pid /var/run/ddns/"$section".dat
    ubus call uci delete "{\"config\":\"ddns\",\"section\":\"$section\"}" 2>/dev/null
    case "$ops" in
        "3") # testing
            ubus call uci add "$json_data"
            ret="$?"
            [ "$ret" != "0" ] && return 1
            $lucihelper -S "$section" -- start
            sleep 10
            pid=$(cat /var/run/ddns/"$section".pid 2>/dev/null)
            ready=$(egrep "good|nochg" /var/run/ddns/"$section".dat 2>/dev/null)
            ubus call uci revert "{\"config\":\"ddns\"}"
            kill -6 "$pid"
            config_log "$pid,$ready,$section"
            [ -z "$pid" -o -z "$ready" ] && return 1
            return 0
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
json_init
json_load "$json_data"

operate_type=""
data=""
json_get_vars operate_type data

config_log "$operate_type" "$data"

case "$operate_type" in
    "3"|"4"|"5")
        if ! handle_ddns "$operate_type" "$data"
        then
            config_log "failed"
            return 1
        fi
        config_log "success"
        return 0
        ;;
    *)
        config_log "unknown type"
        return 1
        ;;
esac

return 0
