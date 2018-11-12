#!/bin/sh

eth=$(ip route list | awk '$1 ~ /default/{print $5;exit}')
[ -z "$eth" ] && eth="eth1"
eth_status=$(ethtool $eth  | awk -F'[ :]+' '/Speed/{speed=$2} /Duplex/{duplex=$2;} END{print speed"|"duplex}')
OIFS=$IFS;IFS='|';set -- $eth_status;eth_speed=$1;eth_duplex=$2;IFS=$OIFS
eth_speed=${eth_speed%b/s}
if [ "$eth_duplex"x = "Full"x ]
then
    eth_duplex="FDX"
else
    eth_duplex="HDX"
fi
mac=$(cat /sys/class/net/eth0/address)
serial=`echo $mac | tr -d : | tr '[a-z]' '[A-Z]'`
cpu="$(cat /proc/cpuinfo | awk -F':' '/model name/{print $2;exit}' | awk '{print $1,$2,$4,$6}')"
mem="$(cat /proc/meminfo | awk '/MemTotal/{a=$2/1024/1024;if(a != int(a)) a=a+1;print int(a)"G";exit}')"
echo -e "config productinfo productinfo"
echo -e  "\toption production OAKGW"
echo -e  "\toption model MTK_OAKGW"
echo -e "\toption serial ${serial}"
echo -e "\toption mac ${mac}"
echo -e "\toption swversion `cat /etc/issue`"
bootversion=$(cat /etc/issue 2>/dev/null)
[ -n "$bootversion" ] && echo -e "\toption bootversion $bootversion"
[ -n "$cpu" ] && echo -e "\toption cpu \"$cpu\""
[ -n "$mem" ] && echo -e "\toption mem \"$mem\""
[ -n "$eth" ] && echo -e "\toption eth_port \"$eth\""
[ -n "$eth_speed" ] && echo -e "\toption port_status \"$eth_speed $eth_duplex\""

