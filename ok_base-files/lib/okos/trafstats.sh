#!/bin/sh

. /lib/functions.sh
. /lib/functions/network.sh

config_load network
config_get _ifname wan ifname

function enable_wan_stats()
{
    iptables -S wan_downlink_stats_rule 2>&1 | grep "${_ifname}" >/dev/null 2>&1
    if [ "$?" == "1" ]
    then
        iptables -I wan_uplink_stats_rule -o ${_ifname}
        iptables -I wan_downlink_stats_rule -i ${_ifname}
    fi
}

function disable_wan_stats()
{
    iptables -F wan_uplink_stats_rule
}

function fetch_wan_stats()
{
    uplink_var="$1"
    downlink_var="$2"

    unset "${uplink_var}"
    unset "${downlink_var}"
    export "${uplink_var}=$(iptables -L wan_uplink_stats_rule -n -v --line-number -x | awk '/'"${_ifname}"'/{print $3}')"
    export "${downlink_var}=$(iptables -L wan_downlink_stats_rule -n -v --line-number -x | awk '/'"${_ifname}"'/{print $3}')"
    iptables -Z wan_downlink_stats_rule
    iptables -Z wan_uplink_stats_rule
}

function enable_lan_stats()
{

    local ip_mac_ints=$(awk '$6 !~ '"${_ifname}"'{
        if(match($3, "0x2")) {
            print $1"_"$4"_"$6
        }
    }' /proc/net/arp)
    local iptables_info=$(iptables -S forward_uplink_stats_rule)
    for ip_mac_int in ${ip_mac_ints}
    do
        OIFS=$IFS;IFS='_';set -- $ip_mac_int;__ip=$1;__mac=$2;IFS=$OIFS
        echo "$iptables_info" | grep "${__ip}" > /dev/null 2>&1
        if [ "$?" = "1" ]
        then
            iptables -I forward_uplink_stats_rule -s "${__ip}" -o "${_ifname}"
            iptables -I forward_downlink_stats_rule -d "${__ip}" -i "${_ifname}"
        fi
    done
    
    return 0
}

function disable_lan_stats()
{
    iptables -F forward_uplink_stats_rule
    iptables -F forward_downlink_stats_rule
}

function fetch_lan_stats()
{
    local vname="$1"
    local ip_mac_ints=$(awk '$6 !~ '"${_ifname}"'{
        if(match($3, "0x2")) {
            print $1"_"$4"_"$6
        }
    }' /proc/net/arp)
    local _lan_stats=""
    local uplinks=$(iptables -L forward_uplink_stats_rule -n -v --line-number -x )
    local downlinks=$(iptables -L forward_downlink_stats_rule -n -v --line-number -x)
    for ip_mac_int in ${ip_mac_ints}
    do
        OIFS=$IFS;IFS='_';set -- $ip_mac_int;__ip=$1;__mac=$2;IFS=$OIFS
        local _uplink=$(echo "$uplinks" | awk '/'"${__ip}"'/{print $3}')
        local _downlink=$(echo "$downlinks" | awk '/'"${__ip}"'/{print $3}')
        _uplink=${_uplink:=0}
        _downlink=${_downlink:=0}
        append _lan_stats "${ip_mac_int}_${_uplink}_${_downlink}"
    done
    unset "$vname"
    export "${vname}=${_lan_stats}"
    iptables -Z forward_uplink_stats_rule
    iptables -Z forward_downlink_stats_rule
    return 0
}


#enable_wan_stats
#fetch_wan_stats up down
#enable_lan_stats
#fetch_lan_stats lan_stats




