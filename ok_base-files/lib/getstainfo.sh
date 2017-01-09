#!/bin/sh

/lib/genarplist.sh

ath_all=`ifconfig | grep -E 'ath*' | awk '{print $1}'`

         
for ath in $ath_all
do
wlanconfig $ath list sta  | awk -F' ' '$1 !~ /ADDR/{
    print "config client"              
    print "\toption ifname '$ath'"
    print "\toption mac "$1  
    print "\toption chan "$3  
    print "\toption rssi "$6
    print "\toption assoctime "$17
    system("/lib/fetchipbymac.sh "$1)
}' |tee /etc/config/stationinfo 
done

