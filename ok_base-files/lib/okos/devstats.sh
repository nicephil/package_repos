#!/bin/sh


# 1. read config
. /lib/functions.sh
config_load capwapc
config_get mas_server server mas_server
if [ -z "$mas_server" ]
then
    exit
fi

# 4. generate json file
{
    "operate_type":"2" # 2:interface notice,
    "data": "{
    "list": [
    {
        "name":"e0", # e0, switch
        "type":"0", #0:WAN,1:LAN,2:bridge
        "state":"0", #0:disconnected, 1:connected
        "physical_state": "0", #0:down, 1:up
        "bandwidth":"10", #10, 100, 1000(Mbps)
        "duplex": "0", #0:half, 1:full
        "uptime":"20" # uptime
        "dns":["8.8.8.8","114.114.114.114"],
        "mac":"00:11:22:33:44:55",
        "bridge_menbers": [
            "e0",
            "e1"
        ],
        "ips":[
        {
            "proto":"0", #0:dhcp,1:static,2:pppoe
            "pppoe_username":"llwang",
            "pppoe_password":"oakridge",
            "ip":"192.168.254.1",
            "netmask":"255.255.255.0",
            "gateway":"192.168.254.254",
        },
        ],
        [
        {
            "proto":"0", #0:dhcp,1:static,2:pppoe
            "pppoe_username":"llwang",
            "pppoe_password":"oakridge",
            "ip":"192.168.254.1",
            "netmask":"255.255.255.0",
            "gateway":"192.168.254.254",
        },
        ],
    },
    ]
}
}"
}



# wan
# $1: filename
function analyze_wan()
{
    # inherint e_type e_state e_physcal_state e_proto e_device e_uptime
    filename="$1"
    json_init
    json_load "$(cat /tmp/wan.status)"
    e_type=0
    json_get_var e_physical_state  "up"
    e_state = e_physical_state
    json_get_var e_proto "proto"
    json_get_var e_device "device"

    # not up, so there no more data
    [ "$e_physical_state" = "0" -o "$e_proto" = "none" ] && return

    json_get_var e_uptime "uptime"


}

config_load network
local e_type e_state e_physcal_state e_proto e_device
local e_uptime
analyze_wan /tmp/wan.status




# 6. upload json file to nms
URL="http://${mas_server}/nms/api/device/router/interface"
curl -i -X POST -H "'Content-type':'application/x-www-form-urlencoded', 'charset':'utf-8', 'Accept': 'text/plain'" -d "$json" $URL
