#!/bin/sh

help()
{
    cat <<_HELP_
Setup LAN port on static ip mode.
Support create/setup VLAN interface.
lan4053 represents PHY port eth3. It means the native vlan.
LAN port will be added to a security zone, TRUSTED by default.

Usage: $0 [lan4053] IPADDR NETMASK
        -m MTU # Set MTU on this interface
        -v VLANID # vlan id [1~4093] on the target interface
        -z ZONE [TRUSTED|UNTRUSTED|DMZ|GUEST] # assign security zone
        -S # don't restart service
Example:
    $0 lan4053 192.168.254.254 255.255.255.0 # set lan port with static ip addresses
    $0 lan4053 192.168.101.254 255.255.255.0 -v 101 # set vlan 101 interface with static ip addresses
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
vid=''
zone='TRUSTED'
while [ -n "$1" ]; do
    case $1 in
        -m) mtu="$2";shift 2;;
        -v) vid="$2";shift 2;;
        -z) zone="$2";shift 2;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

case $zone in
    TRUSTED) zone_id='0';;
    UNTRUSTED) zone_id='1';;
    DMZ) zone_id='2';;
    GUEST) zone_id='3';;
    *) help; exit 1;;
esac

if [ -n "${vid}" ]; then
    if [ $vid -ge 4096 -o $vid -le 0 ]; then
        help
        exit 1
    else
        ifx="${ifx}_${vid}"
        ifname="${ifname}.${vid}"
    fi
fi
echo $ifx $ifname $ipaddr $netmask

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

uci get firewall.@zone[${zone_id}].network | grep -e "\<${ifx}\>"
if [ "$?" != 0 ]; then
    uci add_list firewall.@zone[${zone_id}].network="${ifx}"
fi 
uci commit firewall

if [ -z "${vid}" ]; then
    # need to adjust router.oakridge.vip --> lanip mapping
    # dhcp.@dnsmasq[0].address='/router.oakridge.vip/172.16.254.254'
    uci set dhcp.@dnsmasq[0].address="/router.oakridge.vip/${ipaddr}"
    uci commit dhcp
    # need to adjust firewall 80 mapping
    # firewall.@redirect[0].dest_ip='172.16.254.254'
    # uci set firewall.@redirect[0].dest_ip="${ipaddr}"
    # uci commit firewall
    # need to update webuiconfig file also
    uci set webui_config.${ifx}.ipaddr="${ipaddr}"
    uci set webui_config.${ifx}.netmask="${netmask}"
    uci commit webui_config
fi

if [ -z "$no_restart" ]; then
    /etc/init.d/network reload
    /etc/init.d/firewall reload
fi

exit 0

