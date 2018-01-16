#!/bin/sh
# Copyright (c) 2013 The Linux Foundation. All rights reserved.
# Copyright (C) 2011 OpenWrt.org

UCIDEF_LEDS_CHANGED=0

ucidef_set_led_netdev() {
	local cfg="led_$1"
	local name=$2
	local sysfs=$3
	local dev=$4
	local mode=$5

	uci -q get system.$cfg && return 0

	uci batch <<EOF
set system.$cfg='led'
set system.$cfg.name='$name'
set system.$cfg.sysfs='$sysfs'
set system.$cfg.trigger='netdev'
set system.$cfg.dev='$dev'
set system.$cfg.mode='${mode:-link tx rx}'
EOF
	UCIDEF_LEDS_CHANGED=1
}

ucidef_set_led_usbdev() {
	local cfg="led_$1"
	local name=$2
	local sysfs=$3
	local dev=$4

	uci -q get system.$cfg && return 0

	uci batch <<EOF
set system.$cfg='led'
set system.$cfg.name='$name'
set system.$cfg.sysfs='$sysfs'
set system.$cfg.trigger='usbdev'
set system.$cfg.dev='$dev'
set system.$cfg.interval='50'
EOF
	UCIDEF_LEDS_CHANGED=1
}

ucidef_set_led_wlan() {
	local cfg="led_$1"
	local name=$2
	local sysfs=$3
	local trigger=$4

	uci -q get system.$cfg && return 0

	uci batch <<EOF
set system.$cfg='led'
set system.$cfg.name='$name'
set system.$cfg.sysfs='$sysfs'
set system.$cfg.trigger='$trigger'
EOF
	UCIDEF_LEDS_CHANGED=1
}

ucidef_set_led_switch() {
	local cfg="led_$1"
	local name=$2
	local sysfs=$3
	local trigger=$4
	local port_mask=$5

	uci -q get system.$cfg && return 0

	uci batch <<EOF
set system.$cfg='led'
set system.$cfg.name='$name'
set system.$cfg.sysfs='$sysfs'
set system.$cfg.trigger='$trigger'
set system.$cfg.port_mask='$port_mask'
EOF
	UCIDEF_LEDS_CHANGED=1
}

ucidef_set_led_timer() {
	local cfg="led_$1"
	local name=$2
	local sysfs=$3
	local delayon=$4
	local delayoff=$5

	uci -q get system.$cfg && return 0

	uci batch <<EOF
set system.$cfg='led'
set system.$cfg.name='$name'
set system.$cfg.sysfs='$sysfs'
set system.$cfg.trigger='timer'
set system.$cfg.delayon='$delayon'
set system.$cfg.delayoff='$delayoff'
EOF
	UCIDEF_LEDS_CHANGED=1
}

ucidef_set_led_default() {
	local cfg="led_$1"
	local name=$2
	local sysfs=$3
	local default=$4

	uci -q get system.$cfg && return 0

	uci batch <<EOF
set system.$cfg='led'
set system.$cfg.name='$name'
set system.$cfg.sysfs='$sysfs'
set system.$cfg.default='$default'
EOF
	UCIDEF_LEDS_CHANGED=1
}

ucidef_set_led_rssi() {
	local cfg="led_$1"
	local name=$2
	local sysfs=$3
	local iface=$4
	local minq=$5
	local maxq=$6
	local offset=$7
	local factor=$8

	uci -q get system.$cfg && return 0

	uci batch <<EOF
set system.$cfg='led'
set system.$cfg.name='$name'
set system.$cfg.sysfs='$sysfs'
set system.$cfg.trigger='rssi'
set system.$cfg.iface='rssid_$iface'
set system.$cfg.minq='$minq'
set system.$cfg.maxq='$maxq'
set system.$cfg.offset='$offset'
set system.$cfg.factor='$factor'
EOF
	UCIDEF_LEDS_CHANGED=1
}

ucidef_set_rssimon() {
	local dev="$1"
	local refresh="$2"
	local threshold="$3"

	local cfg="rssid_$dev"

	uci -q get system.$cfg && return 0

	uci batch <<EOF
set system.$cfg='rssid'
set system.$cfg.dev='$dev'
set system.$cfg.refresh='$refresh'
set system.$cfg.threshold='$threshold'
EOF
	UCIDEF_LEDS_CHANGED=1
}

ucidef_commit_leds()
{
	[ "$UCIDEF_LEDS_CHANGED" == "1" ] && uci commit system
}

ucidef_set_interface_loopback() {
	uci batch <<EOF
set network.loopback='interface'
set network.loopback.ifname='lo'
set network.loopback.proto='static'
set network.loopback.ipaddr='127.0.0.1'
set network.loopback.netmask='255.0.0.0'
EOF
}

ucidef_set_interface_raw() {
	local cfg=$1
	local ifname=$2

	uci batch <<EOF
set network.$cfg='interface'
set network.$cfg.ifname='$ifname'
set network.$cfg.proto='none'
EOF
}

#OK_PATCH
ucidef_set_interface_lan_with_vlan() {
	local ifname=$1
    local vlan=$2

	uci batch <<EOF
set network.lan'$vlan'='interface'
set network.lan'$vlan'.ifname='$ifname'
set network.lan'$vlan'.type='bridge'
set network.lan'$vlan'.proto='dhcp'
set network.lan'$vlan'.dhcp_default_ip="192.168.100.20"
set network.lan'$vlan'.dhcp_default_netmask="255.255.255.0"
set network.lan'$vlan'.igmp_snooping='1'
set network.lan'$vlan'.mtu='1600'
set network.alias='alias'
set network.alias.interface="lan$vlan"
set network.alias.proto='static'
set network.alias.ipaddr='169.254.165.32'
set network.alias.netmask='255.255.255.0'
set network.dwan=interface
set network.dwan.ifname='ath50'
set network.dwan.proto='static'
set network.dwan.ipaddr='192.168.250.100'
set network.dwan.netmask='255.255.255.0'
set network.alias1=alias
set network.alias1.interface='dwan'
set network.alias1.proto='static'
set network.alias1.ipaddr='169.254.250.100'
set network.alias1.netmask='255.255.255.0'

EOF
}
#end of OK_PATCH

ucidef_set_interface_lan() {
	local ifname=$1

	uci batch <<EOF
set network.lan='interface'
set network.lan.ifname='$ifname'
set network.lan.type='bridge'
set network.lan.proto='dhcp'
EOF
}

ucidef_set_interface_wan() {
	local ifname=$1

	uci batch <<EOF
set network.wan='interface'
set network.wan.ifname='$ifname'
set network.wan.proto='dhcp'
EOF
}

ucidef_set_interfaces_lan_wan() {
	local lan_ifname=$1
	local wan_ifname=$2

	ucidef_set_interface_lan "$lan_ifname"
	ucidef_set_interface_wan "$wan_ifname"
}

ucidef_set_interface_bond() {
       local ifname=$1
       local hash_policy=$2
       local slave_list=$3
       local mode=$4
       uci batch <<EOF
set network.bond='interface'
set network.bond.ifname='$ifname'
set network.bond.type='bonding'
set network.bond.proto='static'
set network.bond.xmit_hash_policy='$hash_policy'
set network.bond.slaves='$slave_list'
set network.bond.mode='$mode'
EOF
}

ucidef_set_interface_macaddr() {
	local ifname=$1
	local mac=$2

	uci batch <<EOF
set network.$ifname.macaddr='$mac'
EOF
}

ucidef_add_switch() {
	local name=$1
	local reset=$2
	local enable=$3
	uci batch <<EOF
add network switch
set network.@switch[-1].name='$name'
set network.@switch[-1].reset='$reset'
set network.@switch[-1].enable_vlan='$enable'
EOF
}

#OK_PATCH
ucidef_add_switch_vlan_with_name() {
	local device=$1
	local vlan=$2
	local ports=$3
	uci batch <<EOF
set network.vlan'$vlan'=switch_vlan 
set network.vlan'$vlan'.device='$device'
set network.vlan'$vlan'.vlan='$vlan'
set network.vlan'$vlan'.ports='$ports'
EOF
}
#end of OK_PATCH

ucidef_add_switch_vlan() {
	local device=$1
	local vlan=$2
	local ports=$3
	uci batch <<EOF
add network switch_vlan
set network.@switch_vlan[-1].device='$device'
set network.@switch_vlan[-1].vlan='$vlan'
set network.@switch_vlan[-1].ports='$ports'
EOF
}

ucidef_set_snd_ctrl() {
	local card=$1
	local name=$2
	local value=$3
	uci batch <<EOF
add sound sound-control
set sound.@sound-control[-1].card='$card'
set sound.@sound-control[-1].name='$name'
set sound.@sound-control[-1].value='$value'
EOF
}
