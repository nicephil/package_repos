#!/bin/sh

if [ $# -ne 0 ]; then
    echo "Usage: $0 <>"
    exit 1
fi

uci set dhcp.lan4053.ignore="1"
uci set dhcp.@dnsmasq[0].notinterface="wan wan1 wan2 lan4053"
uci commit dhcp

# need to update webui_config
uci set webui_config.lan4053.dhcp_server_enable="0"
uci commit webui_config


/etc/init.d/dnsmasq restart
/etc/init.d/network reload



