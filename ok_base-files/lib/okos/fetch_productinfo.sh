#!/bin/sh

board=$(cat /tmp/sysinfo/board_name)

case "$board" in
HCMT7621-N256)
    mac=$(hexdump -e '1/1 "%02x:"' -n6 /dev/mtd2)
    mac=${mac%:*}
    mac=`echo $mac |tr '[a-z]' '[A-Z]'`
    serial=`echo $mac |tr -d :`
    model="$board"
    echo -e "config productinfo productinfo"
    echo -e  "\toption production ${model}"
    echo -e  "\toption model MTK_${model}"
    echo -e "\toption serial ${serial}"
    echo -e "\toption mac ${mac}"
    ;;
*)
    ;;
esac

echo -e "\toption bootversion `cat /etc/issue`"

