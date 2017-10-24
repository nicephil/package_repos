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

    # ignore no-existing ath interface
    ifconfig "$section" > /dev/null 2>&1
    if [ "$?" = "1" ]
    then
        return 0
    fi

    if [ -z "$var" ]
    then
        if [ "$_type" = "1" ]
        then
            _has_guestnet=1
            return 1
        fi
        return 0
    fi

    config_get _lan "$section" "network"
    case "$var""$_type" in
        "00"|"01"|"10"|"1"|"0") # no isolation
            # 1. check and remove ath from gre bridge
            brctl show "br-gre4000" | grep "$section" > /dev/null 2>&1
            if [ "$?" = "0" ]
            then
                brctl delif "br-gre4000" "$section"
            fi
            # 2. check and add ath into normal bridge
            brctl show "br-${_lan}" | grep "$section" > /dev/null 2>&1
            if [ "$?" = "1" ]
            then
                brctl addif "br-${_lan}" "$section" > /dev/null 2>&1
            fi
            ;;
        "11") # isolation, and guest network
            # 1. create gre bridge
            brctl show | grep "br-gre4000" > /dev/null 2>&1
            if [ "$?" = "1" ]
            then
                brctl addbr "br-gre4000"
            fi
            # 2. add virtual gre interface
            ip link show "gre4tap" >/dev/null 2>&1
            if [ "$?" = "1" ]
            then
                ip link add "gre4tap" type gretap remote "$_gateway" local "$_ipaddr"
                ip link set "gre4tap" up
            fi
            # 3. add related gre interface to gre bridge
            brctl show "br-gre4000" | grep "gre4tap" > /dev/null 2>&1
            if [ "$?" = "1" ]
            then
                brctl addif "br-gre4000" "gre4tap"
            fi
            # 4. remvoe from existing bridge
            brctl show "br-${_lan}" | grep "$section" > /dev/null 2>&1
            if [ "$?" = "0" ]
            then
                brctl delif "br-${_lan}" "$section"
            fi
            # 4. add related ath interface to gre bridge
            brctl show "br-gre4000" | grep "$section" > /dev/null 2>&1
            if [ "$?" = "1" ]
            then
                brctl addif "br-gre4000" "$section" > /dev/null 2>&1
            fi
            ;;
        "*")
            echo "unknown isolation type"
            ;;
    esac

    return 0
}

config_load wireless
config_foreach check_guestnetwork "wifi-iface"

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


