#!/bin/sh

. /lib/ramips.sh

board=$(ramips_board_name)

case "$board" in
ubnt-erx)
    mac=$(hexdump -e '1/1 "%02x:"' -n6 /dev/mtd2)
    mac=${mac%:*}
    mac=`echo $mac|tr '[a-z]' '[A-Z]'`
    serial=`echo $mac |tr -d :`
    echo -e "config productinfo productinfo"
    echo -e  "\toption production EdgeRouter_ER-X"
    echo -e  "\toption model UBNT_EdgeRouter_ER-X"
    echo -e "\toption serial ${serial}"
    echo -e "\toption mac ${mac}"
    ;;

miwifi-3)
    mac=$(cat /sys/class/net/eth0/address)
    mac=`echo $mac|tr '[a-z]' '[A-Z]'`
    serial=`echo $mac | tr -d :`
    echo -e "config productinfo productinfo"
    echo -e  "\toption production miwifi3"
    echo -e "\toption serial ${serial}"
    echo -e "\toption mac ${mac}"
    ;;

*)
    ;;
esac

echo -e "\toption bootversion `cat /etc/issue`"



