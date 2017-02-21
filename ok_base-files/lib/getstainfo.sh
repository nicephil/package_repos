#!/bin/sh

if [[ -f /tmp/getstainfo.lock ]]
then
    exit 0
fi

touch /tmp/getstainfo.lock

ath_all=`ifconfig | grep -E 'ath*' | awk '{print $1}'`


mkdir -p /tmp/stationinfo
         
for ath in $ath_all
do
wlanconfig $ath list sta  | awk -F' ' '$1 !~ /ADDR/{
    mac=$1;
    gsub(/:/,"",mac);
    print "config client "mac;              
    print "\toption ifname '$ath'";
    print "\toption mac "$1;
    print "\toption chan "$3;  
    print "\toption rssi "$6;
    print "\toption assoctime "$17;
    system("/lib/fetchipbymac.sh "$1);
    system("/lib/fetchinfobyinterface.sh '$ath'");
}'
done > /tmp/stationinfo/stationinfo

rm -rf /tmp/getstainfo.lock
