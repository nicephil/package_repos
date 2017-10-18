#!/bin/sh

DEBUG="$1"
[ -n "$DEBUG" ] && {
    export 'json_data={"data":"","operate_type":9}'
    #export 'json_data={"data":"{\"config\":\"ddns\",\"name\":\"ddns_test\",\"type\":\"service\",\"values\":{\"enabled\":\"1\",\"username\":\"largepuppet\",\"password\":\"wodemima\",\"service_name\":\"3322.org\",\"domain\":\"largepuppet.f3322.net\",\"interface\":\"wan\",\"lookup_host\":\"largepuppet.f3322.net\"}}","operate_type":3}'
    #export 'json_data={"data":"{\"config\":\"firewall\",\"name\":\"portforwarding_3\",\"type\":\"redirect\",\"values\":{\"src\":\"wan\",\"proto\":\"tcp\",\"dest\":\"lan\",\"display_name\":\"ssh\",\"src_dport\":\"2222\",\"dest_ip\":\"172.16.254.254\",\"dest_port\":\"22\"}}","operate_type":6}'
    #export 'json_data={"data":"{\"actions\":[{\"action\":0,\"data\":\"{\\\"enabled\\\":\\\"1\\\",\\\"interface\\\":\\\"wan\\\"}\"},{\"action\":1,\"data\":\"{\\\"enabled\\\":\\\"0\\\",\\\"interface\\\":\\\"lan4000\\\"}\"}]}","operate_type":"8"}'
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

function handle_port_forwarding()
{
    local ops="$1"
    local json_data="$2"
    local section=""
    local name=""
    local ret=""
    json_init
    json_load "$json_data"
    json_get_vars name
    section="$name"
    ubus call uci delete "{\"config\":\"firewall\",\"section\":\"$section\"}" 2>/dev/null
    case "$ops" in
        "6") # config
            ubus call uci add "$json_data"
            ret="$?"
            [ "$ret" != "0" ] && return 1
            ubus call uci commit "{\"config\":\"firewall\"}"
            /etc/init.d/firewall reload
            return 0
            ;;
        "7") # delete
            ubus call uci delete "{\"config\":\"firewall\",\"section\":\"$section\"}"
            ret="$?"
            [ "$ret" != "0" ] && return 1
            ubus call uci commit "{\"config\":\"firewall\"}"
            return 0
            ;;
    esac
    return 0
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
            ubus call uci delete "{\"config\":\"ddns\",\"section\":\"$section\"}" 2>/dev/null
            ubus call uci commit "{\"config\":\"ddns\"}"
            kill -6 "$pid"
            rm -rf /var/run/ddns/"$section".pid /var/run/ddns/"$section".dat
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

function handle_common_action()
{
    local ops="$1"
    local json_data="$2"
    local ret=""
    json_init
    json_load "$json_data"
	if json_is_a actions array; then
		json_get_keys actions actions
		json_select actions

		for act in $actions
        do
			json_select "$act"
                local action=""
                json_get_vars action
                local data=""
				json_get_vars data
                case "$action" in 
                    "1")
                        ubus call uci add "$data"
                        ;;
                    "2")
                        ubus call uci delete "$data"
                        ;;
                    "*")
                        config_log "unknown action $action"
                        uci revert
                        return 0
                        ;;
                esac
			json_select ..
		done
		json_select ..

        uci commit
        /etc/init.d/network reload
        /etc/init.d/dnsmasq reload
	fi
    return 0
}

function handle_queryif()
{
    local ops="$1"
    local json_data="$2"
    local ret=""
    has_ifjson=1 /lib/okos/devstats.sh
    return 0
}

function handle_queryclient()
{
    local ops="$1"
    local json_data="$2"
    local ret=""
    has_ifjson=0 has_clientjson=1 /lib/okos/devstats.sh 
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
    "1")
        if ! handle_queryif "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;

    "3"|"4"|"5")
        if ! handle_ddns "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;
    "6"|"7")
        if ! handle_port_forwarding "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;
    "8")
        if ! handle_common_action "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;
    "9")
        if ! handle_queryclient "$operate_type" "$data"
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
