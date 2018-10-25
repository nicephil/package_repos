#!/bin/sh

help()
{
    cat <<_HELP_
Setup/Remove LAN port on static ip mode.
Support create/setup VLAN interface.
lan4053 represents PHY port eth3. It means the native vlan.
LAN port will be added to a security zone, TRUSTED by default.

Usage: $0 {lan4053} [--ipaddr IPADDR] [--netmask NETMASK] [--mtu MTU] [--vid VLANID] [--zone ZONE] [-RS]
        --ipaddr IPADDR # static ipaddress
        --netmask NETMASK # format 255.255.255.0
        --mtu MTU # Set MTU on this interface
        --vid VLANID # vlan id [1~4093] on the target interface
        --zone {TRUSTED|UNTRUSTED|DMZ|GUEST} # assign security zone
        -R # disable this vlan
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
shift 1

zone='TRUSTED'
while [ -n "$1" ]; do
    case $1 in
        --ipaddr) ipaddr="$2";shift 2;;
        --netmask) netmask="$2";shift 2;;
        --mtu) mtu="$2";shift 2;;
        --vid) vid="$2";shift 2;;
        --zone) zone="$2";shift 2;;
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

if [ -z "$remove" ]; then
    [ -n "$ipaddr" -a -n "$netmask" ] || exit 1

    uci delete network.${ifx}
    uci set network.${ifx}=interface
    uci set network.${ifx}.ifname=${ifname}
    uci set network.${ifx}.proto='static'
    uci set network.${ifx}.ipaddr="${ipaddr}"
    uci set network.${ifx}.netmask="${netmask}"
    if [ -n "$mtu" ]; then
        uci set network.${ifx}.mtu=$mtu
    fi
    uci get firewall.${zone}.network | grep -e "\<${ifx}\>" > /dev/null
    if [ "$?" != 0 ]; then
        uci add_list firewall.${zone}.network="${ifx}"
    fi 

    if [ -z "${vid}" ]; then
        # need to adjust router.oakridge.vip --> lanip mapping
        # dhcp.okos_router.ip='172.16.254.254'
        uci set dhcp.okos_router.ip="${ipaddr}"
        uci commit dhcp
        # need to update webuiconfig file also
        uci set webui_config.${ifx}.ipaddr="${ipaddr}"
        uci set webui_config.${ifx}.netmask="${netmask}"
        uci commit webui_config
    fi

else
    uci delete network.${ifx}
    uci del_list firewall.${zone}.network="${ifx}"
fi

uci commit network
uci commit firewall

if [ -z "$no_restart" ]; then
    /etc/init.d/network reload
    /etc/init.d/dnsmasq reload
    /etc/init.d/firewall reload
fi

echo "Set IP $ipaddr/$netmask on $ifx : $vid"

exit 0

