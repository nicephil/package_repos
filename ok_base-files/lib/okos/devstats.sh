#!/bin/sh

# 0. include modules

. /lib/functions.sh
. /lib/functions/network.sh
. /usr/share/libubox/jshn.sh

json_select_array() {
	local _json_no_warning=1

	json_select "$1"
	[ $? = 0 ] && return

	json_add_array "$1"
	json_close_array

	json_select "$1"
}

json_select_object() {
	local _json_no_warning=1

	json_select "$1"
	[ $? = 0 ] && return

	json_add_object "$1"
	json_close_object

	json_select "$1"
}


# 1. read config

config_load capwapc
config_get mas_server server mas_server
if [ -z "$mas_server" ]
then
    exit
fi

config_load productinfo
config_get mac productinfo mac
if [ -z "$mac" ]
then
    exit
fi


function add_list_into_json_array()
{
    local value="$1"
    local array_name="$2"

    json_select_array "$array_name"
        json_add_string _ "$value"
    json_select ..
}

function fetch_ddns_config()
{
    local section="$1"
    local __tmp1=""
    json_add_object
    json_add_string key "$section"
    config_get __tmp1 "$section" service_name
    json_add_string service_name "$__tmp1"
    config_get __tmp1 "$section" domain
    json_add_string domain "$__tmp1"
    config_get __tmp1 "$section"  username
    json_add_string username "$__tmp1"
    config_get __tmp1 "$section" password
    json_add_string password "$__tmp1"
    local pid=$(cat /var/run/ddns/"$section".pid 2>/dev/null)
    local upt=$(cat /var/run/ddns/"$section".update 2>/dev/null)
    __tmp1=$(egrep 'good|nochg' /var/run/ddns/"$section".dat 2>/dev/null)
    if [ -z "$pid" -o -z "$upt" -o -z "$__tmp1"]
    then
        json_add_int state 0
        json_add_int update_time 0
    else
        json_add_int state 1
        json_add_init update_time "$upt"
    fi
    json_close_object
}


# 4. generate json file
function generate_json()
{

network_get_interfaces ifcs

json_init
json_select_array list
local ifc
for ifc in ${ifcs} 
do
    json_add_object
    local _tmp1 _tmp2 _tmp3
    local ifname
    network_get_device ifname "$ifc"
    json_add_string ifname "$ifname"

    network_get_lname _tmp1 "$ifname"
    json_add_string name "$_tmp1"

    local proto
    network_get_protocol proto "$ifc"
    json_add_string proto "$proto"

    # 0:WAN,1:LAN,2:BRIDGE
    local l_type
    case "$ifc" in
        'lan4000')
            l_type='2'
            ;;
        'lan40[0-9].*')
            l_type='1'
            ;;
        'wan')
            l_type='0'
            ;;
        *)
            l_type=''
            ;;
    esac
    if [ "$proto" = "none" ]
    then
        l_type = '3'
    fi
    json_add_int "type" "$l_type"

    network_get_status _tmp1 "$ifc"
    json_add_int state "$_tmp1"

    local state
    network_get_phy_status state _tmp2 _tmp3 "$ifname"
    json_add_int physical_state "$state"
    json_add_int bandwidth "$_tmp2"
    json_add_int duplex "$_tmp3"

    network_get_uptime _tmp1 "$ifc"
    json_add_int uptime "$_tmp1"


    if [ "$state" = "0" -a "$proto" = "static" ]
    then
        config_list_foreach "$ifc" "dns" add_list_into_json_array "dns"
        network_get_ipaddrs _tmp1 "$ifc"
        json_select_array ips
            json_add_object
                config_load network
                config_get _tmp1 "$ifc" ipaddr
                json_add_string ip "$_tmp1"
                config_get _tmp1 "$ifc" netmask
                json_add_string netmask "$_tmp1"
                config_get _tmp1 "$ifc" gateway
                json_add_string gateway "$_tmp1"
                if [ "$l_type" = "0" ]
                then
                    json_select_array ddnss
                    config_load ddns
                    config_foreach fetch_ddns_config service
                    json_select ..
                fi
            json_close_object
        json_select ..
    else
        network_get_dnsserver _tmp1 "$ifc" "true"
        set -- $_tmp1; while [ -n "$1" ]; do add_list_into_json_array "$_tmp1" "dns"; shift; done
        json_select_array ips
            json_add_object
                json_add_string key ""
                config_load network
                config_get _tmp1 "$ifc" username
                json_add_string pppoe_username "$_tmp1"
                config_get _tmp1 "$ifc" password
                json_add_string pppoe_password "$_tmp1"
                network_get_ipaddrs _tmp1 "$ifc"
                json_add_string ip "$_tmp1"
                network_get_netmask _tmp1 "$ifc"
                json_add_string netmask "$_tmp1"
                network_get_gateway _tmp1 "$ifc"
                json_add_string gateway "$_tmp1"
                if [ "$l_type" = "0" ]
                then
                    json_select_array ddnss
                    config_load ddns
                    config_foreach fetch_ddns_config service
                    json_select ..
                fi
            json_close_object
        json_select ..
    fi

    network_get_macaddr _tmp1 "$ifname"
    json_add_string mac "$_tmp1"

    if [ "$l_type" = "2" ]
    then
        network_get_bmembers _tmp1
        set -- $_tmp1; while [ -n "$1" ]; do add_list_into_json_array "e$1" "bridge_members"; shift; done
    fi

    json_close_object
done
json_select ..
export "jsdump=$(json_dump)"
}


generate_json 

# echo "$jsdump"


json_init
json_add_int operate_type "2"
json_add_string mac "$mac"
json_add_string data "$jsdump"

json_data=$(json_dump)

echo $json_data

# 6. upload json file to nms
URL="http://${mas_server}/nms/api/device/router/info"
curl -i -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL
