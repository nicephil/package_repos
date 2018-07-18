#!/bin/sh

mac=$(cat /sys/class/net/eth0/address)
mac=${mac%:*}
serial=`echo $mac | tr -d :`
cpu="$(cat /proc/cpuinfo | awk -F':' '/model name/{print $2;exit}' | awk '{print $1,$2,$4,$6}')"
mem="$(cat /proc/meminfo | awk '/MemTotal/{a=$2/1024/1024;if(a != int(a)) a=a+1;print int(a)"G";exit}')"
echo -e "config productinfo productinfo"
echo -e  "\toption production VPNSRV"
echo -e  "\toption model Oakridge_VPNSRV"
echo -e "\toption serial ${serial}"
echo -e "\toption mac ${mac}"
echo -e "\toption swversion `cat /etc/issue`"
echo -e "\toption  cpu $cpu"
echo -e "\toption mem $mem"

