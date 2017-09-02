#!/bin/sh

. /lib/ramips.sh

board=$(ramips_board_name)

case "$board" in
ubnt-erx)
    mac=$(hexdump -e '1/1 "%x:"' -n6 /dev/mtd2)
    mac=${mac%:*}
    serial=`echo $mac | tr -d :`
    echo -e "config productinfo productinfo"
    echo -e  "\toption production ubnterx"
    echo -e "\toption serial ${serial}"
    echo -e "\toption mac ${mac}"
    ;;
*)
    ;;
esac

echo -e "\toption swversion `cat /etc/issue`"



