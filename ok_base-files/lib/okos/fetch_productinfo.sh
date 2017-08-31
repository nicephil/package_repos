#!/bin/sh

. /lib/ar71xx.sh

board=$(ar71xx_board_name)
model=$(ar71xx_model)

case "$board" in
unifi)
    mac=$(hexdump -e '1/1 "%x:"' -n6 /dev/mtd7)
    mac=${mac%:*}
    serial=`echo $serial|tr -d :`
    echo -e "config productinfo productinfo"
    echo -e  "\toption production ubnt${model}"
    echo -e "\toption serial ${serial}"
    echo -e "\toption mac ${mac}"
    ;;
*)
    strings /dev/mtd5 | awk -F'=' ' 
    BEGIN { print "config productinfo productinfo"; } 
    { 
    if ($1 == "DEV_NAME") 
        print "\toption production "$2;  
    else if ($1 == "DEV_SERIAL_NUMBER") 
        print "\toption serial "$2;  
    else if ($1 == "MAC_ADDRESS") 
        print "\toption mac "$2; 
    else if ($1 == "MAC_ADDRESS_COUNT") 
        print "\toption mac_count "$2; 
    }'
    ;;
esac

echo -e "\toption swversion `cat /etc/issue`"

