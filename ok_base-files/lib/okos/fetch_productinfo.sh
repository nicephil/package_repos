#!/bin/sh

strings /dev/mtd5 | awk -F'=' ' 
BEGIN { print "config productinfo"; } 
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

echo -e "\toption swversion `cat /etc/issue`"
