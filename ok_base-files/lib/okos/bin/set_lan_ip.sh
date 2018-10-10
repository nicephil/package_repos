#!/bin/sh

help()
{
    cat <<_HELP_
Setup LAN port on static ip mode.
Usage: $0 [lan4053] IPADDR NETMASK
        -m MTU # Set MTU on this interface
Example:
    $0 lan4053 192.168.254.254 255.255.255.0 # set lan port with static ip addresses
_HELP_
}


if [ $# -lt 3 ]; then
    help
    exit 1
fi

case $1 in
    lan4053) ifx="$1";ifname="eth3";;
    *) help; exit 1;;
esac
ipaddr="$2"
netmask="$3"
shift 3

mtu=''
while [ -n "$1" ]; do
    case $1 in
        -m) mtu="$2";shift 2;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

uci delete network.${ifx}
uci set network.${ifx}=interface
uci set network.${ifx}.ifname=${ifname}
uci set network.${ifx}.proto='static'
uci set network.${ifx}.ipaddr="${ipaddr}"
uci set network.${ifx}.netmask="${netmask}"

if [ -n "$mtu" ]; then
    uci set network.${ifx}.mtu=$mtu
fi

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
uci set webui_config.${ifx}.ipaddr="${ipaddr}"
uci set webui_config.${ifx}.netmask="${netmask}"
uci commit webui_config

ifconfig eth3 $ipaddr netmask $netmask

/etc/init.d/network reload

exit 0

