#!/bin/sh

. /lib/ar71xx.sh

board=$(ar71xx_board_name)
model=$(ar71xx_model)

case "$board" in
unifi)
    mac=$(hexdump -e '1/1 "%02x:"' -n6 /dev/mtd7)
    mac=${mac%:*}
    mac=`echo $mac | tr '[a-z]' '[A-Z]'`
    serial=`echo $mac |tr -d :`
    model=`echo $model |tr '[a-z]' '[A-Z]'`
    echo -e "config productinfo productinfo"
    echo -e  "\toption production AC-${model}"
    echo -e  "\toption model UBNT_AC-${model}"
    echo -e "\toption serial ${serial}"
    echo -e "\toption mac ${mac}"
    ;;
*)
    strings /dev/mtd5 | awk -F'=' ' 
    BEGIN { print "config productinfo productinfo"; } 
    { 
    if ($1 == "DEV_NAME") {
        print "\toption production "$2;
        if ($2 == "\"WL8200-I2\"") {
            gsub(/"/,"",$2);
            print "\toption model DCN_"$2;
        } else if ($2 == "\"A923\"") {
            print "\toption model DCN_SEAP-380";
        } else {
            gsub(/"/,"",$2);
            print "\toption model QTS_"$2;
        }
    }
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
echo -e "\toption bootversion `cat /overlay/etc/issue`"

