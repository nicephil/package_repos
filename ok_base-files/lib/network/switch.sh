#!/bin/sh
# Copyright (C) 2009 OpenWrt.org
. /lib/ramips.sh

setup_switch_vlan(){
        local vlan
        local vid
        local ports
        local device
        local port_idx

        config_get vlan "$1" vlan
        config_get vid "$1" vid
        config_get ports "$1" ports
        config_get device "$1" device

        swconfig dev "$device" vlan "$vlan" set vid "$vid"
        echo swconfig dev "$device" vlan "$vlan" set vid "$vid"
        swconfig dev "$device" vlan "$vlan" set ports "$ports"
        echo swconfig dev "$device" vlan "$vlan" set ports "$ports"
        for port in $ports
        do
            port_idx=`echo $port|sed 's/[^0-9]//g'`
            if [ $port_idx -le 5 ]; then
                swconfig dev "$device" port "$port_idx" set pvid "$vid"
                echo swconfig dev "$device" port "$port_idx" set pvid "$vid"
            fi
        done

        if [ $vlan -eq 1 ]; then
            swconfig dev "$device" port 6 set pvid "$vid"
            echo swconfig dev "$device" port 6 set pvid "$vid"
            swconfig dev "$device" port 7 set pvid "$vid"
            echo swconfig dev "$device" port 7 set pvid "$vid"
        fi
}

setup_switch_dev() {
	local name
	config_get name "$1" name
	name="${name:-$1}"
    [ -d "/sys/class/net/$name" ] && ip link set dev "$name" up

    board=$(ramips_board_name)
    case $board in
        miwifi-3)
            swconfig dev "$name" load network
            config_foreach setup_switch_vlan switch_vlan
            swconfig dev "$name" set apply
            ;;
        *)
            swconfig dev "$name" load network
            ;;
    esac
}

setup_switch() {
	config_load network
	config_foreach setup_switch_dev switch
}
