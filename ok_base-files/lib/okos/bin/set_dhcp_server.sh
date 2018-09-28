#!/bin/sh

if [ $# -ne 3 ]; then
    echo "Usage: $0 START LIMIT LEASE ( $0 1 200 83400 )"
    exit 1
fi

start="$1"
limit="$2"
leasetime="$3"

uci set dhcp.lan4053=dhcp
uci set dhcp.lan4053.interface='lan4053'
uci set dhcp.lan4053.start="${start}"
uci set dhcp.lan4053.limit="${limit}"
uci set dhcp.lan4053.leasetime="${leasetime}"
uci set dhcp.lan4053.ignore="0"
uci set dhcp.@dnsmasq[0].notinterface="wan wan1 wan2"

uci commit dhcp
# need to update webui_config also
uci set webui_config.lan4053.dhcp_start="${start}"
uci set webui_config.lan4053.dhcp_limit="${limit}"
uci set webui_config.lan4053.dhcp_leasetime="${leasetime}"
uci set webui_config.lan4053.dhcp_server_enable="1"
uci commit webui_config

/etc/init.d/dnsmasq restart

