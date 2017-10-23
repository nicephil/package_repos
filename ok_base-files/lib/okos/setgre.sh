#!/bin/sh

. /lib/functions.sh
. /lib/functions/network.sh
. /usr/share/libubox/jshn.sh

network_get_gateway _gateway lan1
network_get_ipaddr _ipaddr lan1

config_load productinfo
config_get _mac productinfo mac

_timestamp="`date +%s`"
_has_guestnet="0"

check_guestnetwork()
{
    local section="$1"
    local var="$2"

    config_get _type "$section" "type"
    if [ -n "$var" -a "$var" = "0" ]
    then
        if [ "$_type" = "1" ]
        then
            _has_guestnet=1
            return 1
        fi
    elif [ -n "$var" -a "$var" = "1" ]
    then
        if [ "$_type" = "1" ]
        then
            # 1. remvoe from existing bridge
            config_get _lan "$section" "network"
            brctl show "br-${_lan}" | grep "$section" 2>&1 > /dev/null
            if [ "$?" = "0" ]
            then
                brctl delif "br-${_lan}" "$section"
            fi
            # 2. create gre bridge
            brctl show | grep "br-gre4000" 2>&1 > /dev/null
            if [ "$?" = "1" ]
            then
                brctl addbr "br-gre4000"
            fi
            # 3. add virtual gre bridge
            ip link show "gre4tap" 2>&1 >/dev/null
            if [ "$?" = "1" ]
            then
                ip link add "gre4tap" type gretap remote "$_gateway" local "$_ipaddr"
            fi
            ip link set "gre4tap" up
            # 3. add related ath interface to gre bridge
            brctl show "br-gre4000" | grep "gre4tap" 2>&1 > /dev/null
            if [ "$?" = "1" ]
            then
                brctl addif "br-gre4000" "$section"
                brctl addif "br-gre4000" "gre4tap"
            fi
        fi
    fi
    return 0
}

config_load wireless
config_foreach check_guestnetwork "wifi-iface" "0"

json_init
json_add_boolean has_guestnet "$_has_guestnet"
json_add_string macaddr "$_mac"
json_add_string gateway "$_gateway"
json_add_string ipaddr "$_ipaddr"
json_add_int timestamp "$_timestamp"

json_data=$(json_dump)

echo "===>$json_data"

# upload json file to gateway
URL="http://${_gateway}/cgi-bin/luci/okos/setgre"

response=$(curl -s -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL 2>/dev/null)

echo "----->$response"

json_load "$response"
json_get_var _isolate_guest "isolate_guest"

config_load wireless
config_foreach check_guestnetwork "wifi-iface" "$_isolate_guest"


