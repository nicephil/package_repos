#!/bin/sh

if [ $# -ne 2 ]; then
    echo "Usage: $0 IPADDR NETMASK ( $0 172.16.254.254 255.255.255.0 )"
    exit 1
fi

ipaddr="$1"
netmask="$2"

#uci delete network.lan4053
#uci set network.lan4053=interface
#uci set network.lan4053.ifname='eth3'
#uci set network.lan4053.proto='static'
uci set network.lan4053.ipaddr="${ipaddr}"
uci set network.lan4053.netmask="${netmask}"
uci commit network
# need to adjust router.oakridge.vip --> lanip mapping
# dhcp.@dnsmasq[0].address='/router.oakridge.vip/172.16.254.254'
uci set dhcp.@dnsmasq[0].address="/router.oakridge.vip/${ipaddr}"
uci commit dhcp
# need to adjust firewall 80 mapping
# firewall.@redirect[0].dest_ip='172.16.254.254'
uci set firewall.@redirect[0].dest_ip="${ipaddr}"
uci commit firewall
# need to update webuiconfig file also
uci set webui_config.lan4053.ipaddr="${ipaddr}"
uci set webui_config.lan4053.netmask="${netmask}"
uci commit webui_config

ifconfig eth3 $ipaddr netmask $netmask

/etc/init.d/network reload

