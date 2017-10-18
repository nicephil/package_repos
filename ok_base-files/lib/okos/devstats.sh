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
function generate_ifjson()
{
    local vname="$1"

    network_get_interfaces ifcs

    json_init
    json_select_array list
    local ifc
    for ifc in ${ifcs} 
    do
        # 0:WAN,1:LAN,2:BRIDGE,3:FREE,4:GRE
        local l_type=''
        case "$ifc" in
            'lan4000'|'lan4001')
                l_type='2'
                ;;
            'lan405'*)
                l_type='1'
                ;;
            'wan')
                l_type='0'
                ;;
            'gre'*)
                l_type='4'
                ;;
            *)
                l_type=''
                ;;
        esac

        local proto
        network_get_protocol proto "$ifc"

        if [ "$proto" = "none" ]
        then
            l_type='3'
        fi

        # gre port status fetched from config
        if [ "$l_type" = "4" ]
        then
            continue
        fi

        json_add_object
        local _tmp1 _tmp2 _tmp3
        local ifname _lname
        network_get_device ifname "$ifc"
        json_add_string ifname "$ifname"

        network_get_lname _lname "$ifname"
        json_add_string name "$_lname"

        json_add_string proto "$proto"
        
        json_add_int "type" "$l_type"

        local state
        network_get_phy_status state _tmp2 _tmp3 "$ifname"
        json_add_int physical_state "$state"
        json_add_int bandwidth "$_tmp2"
        json_add_int duplex "$_tmp3"

        # make sure lan state same as physical state
        if [ "$l_type" = "1" ]
        then
            _tmp1="$state"
        else
            network_get_status _tmp1 "$ifc"
        fi
        json_add_int state "$_tmp1"

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
            config_load dhcp
            config_get _tmp1 "$ifc" start
            json_add_int dhcp_start "$_tmp1"
            config_get _tmp1 "$ifc" limit
            json_add_int dhcp_limit "$_tmp1"
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
            config_load dhcp
            config_get _tmp1 "$ifc" start
            json_add_int dhcp_start "$_tmp1"
            config_get _tmp1 "$ifc" limit
            json_add_int dhcp_limit "$_tmp1"
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

        # check related gre bridge, and read config
        if [ "$l_type" = "1" -o "$l_type" = "2" ]
        then
            local grebr="gre${ifc:3}"
            local grebrlname="${_lname}.guest"
            config_load network
            local _ipaddr
            config_get _ipaddr "$grebr" ipaddr
            if [ -n "$_ipaddr" ]
            then
                json_add_object
                json_add_string name "$grebrlname"
                json_add_int "type" "4"
                json_add_int state  "1"
                json_add_int physical_state "1"
                json_add_string proto "static"
                json_select_array ips
                    json_add_object
                    json_add_string key ""
                    json_add_string ip "$_ipaddr"
                    config_get _tmp1 "$grebr" netmask
                    json_add_string netmask "$_tmp1"
                    config_load dhcp
                    config_get _tmp1 "$grebr" start
                    json_add_int dhcp_start "$_tmp1"
                    config_get _tmp1 "$grebr" limit
                    json_add_int dhcp_limit "$_tmp1"
                    json_close_object
                json_select ..
                json_close_object
            fi
        fi
    done
    json_select ..

    export "$vname=$(json_dump)"
    return 0
}

function generate_clientjson()
{
    local vname="$1"
    json_init
    json_add_int type 0
    local dhcp_leases=`awk '{print $1"_"$2"_"$3"_"$4"_"$5}' /tmp/dhcp.leases`
    local dhcp_config=`uci show dhcp`

    json_select_array "list"
    for line in `echo $dhcp_leases`
    do
        local __mac __ip __hostname
        OIFS=$IFS;IFS='_';set -- $line;__mac=$2;__ip=$3;__hostname=$4;IFS=$OIFS
        __hostname=$(echo "$line" | awk -F'_' '{if(!match($4,"*"))print $4}')
        local __lname=$(echo "$dhcp_config" | awk -F '.' '/'"${__ip}"'/{print $2}')
        if [ -z "$__lname" ]
        then
            json_add_object
            json_add_string mac "$__mac"
            [ -n "$__hostname" ] && json_add_string hostname "$__hostname"
            json_add_string ip "$__ip"
            json_add_int lock "0"
            json_close_object
        fi
    done

    for __line in `echo "$dhcp_config" | awk -F'=' '/ip=/{print $0}'`
    do
        local __tmp1 __tmp2
        OIFS=$IFS;IFS='=';set -- $__line;__tmp1=$1;__tmp2=$2;IFS=$OIFS
        local __ip=`echo $__tmp2 | tr -d "'"`
        local __lan __mac
        OIFS=$IFS;IFS='[._]';set -- $__tmp1;__lan=$2;__mac=$3;IFS=$OIFS
        json_add_object
        json_add_string mac "${__mac:0:2}:${__mac:2:2}:${__mac:4:2}:${__mac:6:2}:${__mac:8:2}:${__mac:10:2}"
        config_load dhcp
        config_get __tmp1 "${__lan}_${__mac}" name
        [ -n "$_tmp1" ] && json_add_string hostname "$__tmp1"
        json_add_string ip "$__ip"
        json_add_int lock "1"
        json_close_object
    done

    json_select ..
    export "$vname=$(json_dump)"
}

has_ifson=${has_ifjson:=1}
generate_ifjson ifjson


generate_clientjson clientjson

# 5. final json data
json_init
json_select_array "list"
if [ "$has_ifjson" = "1" ]
then
    json_add_object
    json_add_int operate_type "2"
    json_add_string mac "$mac"
    json_add_string data "$ifjson"
    json_close_object
fi
if [ "$has_clientjson" = "1" ]
then
    json_add_object
    json_add_int operate_type "10"
    json_add_string mac "$mac"
    json_add_string data "$clientjson"
    json_close_object
fi
json_select ..

json_data=$(json_dump)

echo $json_data

# 6. upload json file to nms
URL="http://${mas_server}/nms/api/device/router/info"
curl -i -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL
