#!/bin/sh

if [[ -f /tmp/ifaceinfo.lock ]]
then
    exit 0
fi

touch /tmp/ifaceinfo.lock

mkdir -p /tmp/ifaceinfo
         
{

iwconfig 2> /dev/null | awk '{
                              
if (match($1,"ath")) {        
    print "config "$1" "$1;
    print "\toption ssid "substr($4,7);
    system("(. /lib/functions.sh;config_load wireless;config_get  _vlan "$1" network;echo \"\toption vlan \"${_vlan:3};)");

    while(getline > 0 && length($0) > 0) {
        if (match($4,"Access")) {
            print "\toption mac "$6;
            continue;
        }
        if (match($4,"Tx-Power")) {
            print "\toption txpower "substr($4,10);
            continue;
        }
    }    
}    
 
}'
  
  
[ -n "$1" ] && {
ifconfig 2> /dev/null | awk '{
                              
if (match($1,"eth") || match($1,"br-lan")) {
    if (match($1,"br-lan")) {               
        print "config "substr($1,4)" "substr($1,4);
    } else {                                       
        print "config "$1" "$1;
    }                          
    print "\toption mac "$5;
    while (getline > 0 && length($0) > 0) {
        if (match($1, "inet") && !match($1,"inet6") && match($2,"addr")) {
            print "\toption ipaddr "substr($2,6);
            print "\toption mask "substr($4,6);
            continue;
        }
    }    
}    
 
}'
}

} > /tmp/ifaceinfo/ifaceinfo

rm -rf /tmp/ifaceinfo.lock


