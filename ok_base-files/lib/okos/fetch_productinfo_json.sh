#!/bin/sh

base_dir="/"
eth=$(ip route list | awk '$1 ~ /default/{print $5;exit}')
eth_status=$(ethtool $eth  | awk -F'[ :]+' '/Speed/{speed=$2} /Duplex/{duplex=$2;} END{print speed"|"duplex}')
OIFS=$IFS;IFS='|';set -- $eth_status;eth_speed=$1;eth_duplex=$2;IFS=$OIFS
eth_speed=${eth_speed%b/s}
if [ "$eth_duplex"x = "Full"x ]
then
    eth_duplex="FDX"
else
    eth_duplex="HDX"
fi
mac=$(ip link show dev $eth | awk '/link\/ether/{print $2}')
mac=`echo $mac |tr '[a-z]' '[A-Z]'`
cpu="$(cat /proc/cpuinfo | awk -F':' '/model name/{print $2;exit}' | awk '{print $1,$2,$4,$6}')"
mem="$(cat /proc/meminfo | awk '/MemTotal/{a=$2/1024/1024;if(a != int(a)) a=a+1;print int(a)"G";exit}')"
serial=`echo $mac |tr -d :`
hostname "$serial"
echo $serial > /etc/hostname
if [ -f "$base_dir/etc/issue_boot" ]
then
    bootversion="$(cat $base_dir/etc/issue_boot)"
else
    if [ -f "/etc/redhat-release" ]
    then
        bootversion="$(cat /etc/redhat-release)"
    else
        bootversion="$(cat /etc/issue)"
    fi
fi

bootversion=$(echo $bootversion | sed -e 's/\\/\\\\/g')

if [ -f "$base_dir/etc/issue" ]
then
    swversion="$(cat $base_dir/etc/issue)"
    echo "{\"production\":\"VPNSRV\",\"model\":\"Oakridge_VPNSRV\",\"mac\":\"$mac\",\"serial\":\"$serial\",\"bootversion\":\"$bootversion\", \"swversion\":\"$swversion\", \"cpu\":\"$cpu\", \"mem\":\"$mem\", \"eth_port\":\"$eth\", \"port_status\": \"$eth_speed $eth_duplex\"}"
else
    echo "{\"production\":\"VPNSRV\",\"model\":\"Oakridge_VPNSRV\",\"mac\":\"$mac\",\"serial\":\"$serial\",\"bootversion\":\"$bootversion\", \"cpu\":\"$cpu\", \"mem\":\"$mem\", \"eth_port\":\"$eth\", \"port_status\": \"$eth_speed $eth_duplex\"}"
fi
