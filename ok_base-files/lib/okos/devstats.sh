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

config_load network

add_list_into_json_array()
{
    local value="$1"
    local array_name="$2"

    json_select_array "$array_name"
        json_add_string _ "$value"
    json_select ..
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

    # 0:WAN,1:LAN,2:BRIDGE
    local l_type
    case "$ifc" in
        'lan')
            l_type='2'
            ;;
        'lan[0-9].*')
            l_type='1'
            ;;
        'wan')
            l_type='0'
            ;;
        *)
            l_type=''
            ;;
    esac
    json_add_string "type" "$l_type"

    network_get_status _tmp1 "$ifc"
    json_add_int state "$_tmp1"

    local state
    network_get_phy_status state _tmp2 _tmp3 "$ifname"
    json_add_int physical_state "$state"
    json_add_int bandwidth "$_tmp2"
    json_add_int duplex "$_tmp3"

    network_get_uptime _tmp1 "$ifc"
    json_add_int uptime "$_tmp1"

    local proto
    network_get_protocol proto "$ifc"
    json_add_string proto "$proto"

    if [ "$state" = "0" -a "$proto" = "static" ]
    then
        config_list_foreach "$ifc" "dns" add_list_into_json_array "dns"
        network_get_ipaddrs _tmp1 "$ifc"
        json_select_array ips
            json_add_object
                config_get _tmp1 "$ifc" ipaddr
                json_add_string ip "$_tmp1"
                config_get _tmp1 "$ifc" netmask
                json_add_string netmask "$_tmp1"
                config_get _tmp1 "$ifc" gateway
                json_add_string gateway "$_tmp1"
            json_close_object
        json_select ..
    else
        network_get_dnsserver _tmp1 "$ifc" "true"
        set -- $_tmp1; while [ -n "$1" ]; do add_list_into_json_array "$_tmp1" "dns"; shift; done
        json_select_array ips
            json_add_object
                json_add_string key ""
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

# echo $json_data

# WAN

exit

# 6. upload json file to nms
URL="http://${mas_server}/nms/api/device/router/interface"
curl -i -X POST -H "'Content-type':'application/x-www-form-urlencoded', 'charset':'utf-8', 'Accept': 'text/plain'" -d "$json_data" $URL
