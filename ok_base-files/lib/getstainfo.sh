#!/bin/sh

if [[ -f /tmp/getstainfo.lock ]]
then
    exit 0
fi

touch /tmp/getstainfo.lock

mkdir -p /tmp/stationinfo
         
sqlite3 /tmp/stationinfo.db 'SELECT * FROM STAINFO' | awk -F'|' '{
    mac=$1;
    gsub(/:/,"",mac);
    print "config client "mac;              
    print "\toption mac "$1;
    print "\toption ifname "$2;
    print "\toption chan "$3;  
    print "\toption radioid "$6;
    print "\toption bssid "$7;
    print "\toption authentication "$9;
    print "\toption portal_scheme "$10;
    print "\toption ssid "$11;
    print "\toption vlan "$12;
    print "\toption portal_mode "$13;
    print "\toption portal_user "$14;
    system("/lib/updatefields.sh "$1" "$2" "$11" "$12" "$8);
}' > /tmp/stationinfo/stationinfo

rm -rf /tmp/getstainfo.lock
