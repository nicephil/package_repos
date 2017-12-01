#!/bin/sh

if [[ -f /tmp/ifaceinfo.lock ]]
then
    exit 0
fi

trap 'getifaceinfo_trap; exit' INT TERM ABRT QUIT ALRM

getifaceinfo_trap () {
    logger -t getifaceinfo "gets trap"
    rm -rf /tmp/ifaceinfo.lock
}


touch /tmp/ifaceinfo.lock




dbfile="/tmp/ifaceinfo.db"
tablename="IFINFO"

#CREATE TABLE IFINFO(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);
if [ ! -f "$dbfile" ]
then
    #echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);COMMIT;" | logger
    sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);COMMIT;" 
else
    #echo sqlite3  $dbfile "BEGIN TRANSACTION;DROP TABLE ${tablename};COMMIT;" | logger
    sqlite3  $dbfile "BEGIN TRANSACTION;DROP TABLE ${tablename};COMMIT;" 
    #echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);COMMIT;" | logger
    sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);COMMIT;" 
fi

. /lib/functions.sh

config_load wireless

for i in `seq 0 1`
do
    ifname="wifi$i"
    state="1"
    mac=""
    chan=""
    txpower=""
    mode=""
    bandwidth=""
    config_get _disabled $ifname disabled
    [ "$_disabled" = "1" ] && state="0"
    config_get mac $ifname macaddr
    config_get chan $ifname channel
    config_get txpower $ifname txpower
    [ "$txpower" = "auto" ] && txpower="20"
    config_get mode $ifname hwmode
    config_get bandwidth $ifname htmode
        
    #echo sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\");COMMIT"
    sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\");COMMIT"

done
 

iwconfig 2> /dev/null | awk '{
                              
if (match($1,"ath") && !match($1, "ath50") && !match($1, "ath60")) {        
    ifname=mac=vlan=ssid=ipaddr=maskaddr=chan=txpower=mode=bandwidth="";
    radio_index=substr($1,4,1)
    "(. /lib/functions.sh;config_load wireless;config_get  _vlan "$1" network;echo $_vlan;)" | getline vlan
    "(. /lib/functions.sh;config_load wireless;config_get  _chan wifi"radio_index" channel;echo $_chan;)" | getline chan
    "(. /lib/functions.sh;config_load wireless;config_get  _mode wifi"radio_index" hwmode;echo $_mode;)" | getline mode
    "(. /lib/functions.sh;config_load wireless;config_get  _bandwidth wifi"radio_index" htmode;echo $_bandwidth;)" | getline bandwidth
    ifname=$1;
    ssid=substr($4,7);
    gsub(/"/,"",ssid)

    while(getline > 0 && length($0) > 0) {
        if (match($4,"Access")) {
            mac=$6;
            continue;
        }
        if (match($4,"Tx-Power")) {
            txpower=substr($4,10);
            continue;
        }
    }

    #system("echo sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;INSERT INTO '"${tablename}"' VALUES (\""ifname"\",\"1\",\""mac"\",\""substr(vlan,4)"\",\""ssid"\",\""ipaddr"\",\""maskaddr"\",\""chan"\",\""txpower"\",\""mode"\",\""bandwidth"\");COMMIT'\''");
    system("sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;INSERT INTO '"${tablename}"' VALUES (\""ifname"\",\"1\",\""mac"\",\""substr(vlan,4)"\",\""ssid"\",\""ipaddr"\",\""maskaddr"\",\""chan"\",\""txpower"\",\""mode"\",\""bandwidth"\");COMMIT'\''");
    if (chan && txpower) {
        #system("echo sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;UPDATE '"${tablename}"' SET CHAN=\""chan"\",TXPOWER=\""txpower"\" WHERE IFNAME=\"wifi"radio_index"\";COMMIT'\''");
        system("sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;UPDATE '"${tablename}"' SET CHAN=\""chan"\",TXPOWER=\""txpower"\" WHERE IFNAME=\"wifi"radio_index"\";COMMIT'\''");
    }
}

}'

ifconfig 2> /dev/null | awk '{
                              
if (match($1,"eth") || match($1,"br-lan")) {
    ifname=mac=vlan=ssid=ipaddr=maskaddr=chan=txpower=mode=bandwidth="";
    if (match($1,"br-lan")) {               
        ifname=substr($1,4);
    } else {                                       
        ifname=$1;
    }                          
    mac=$5;
    while (getline > 0 && length($0) > 0) {
        if (match($1, "inet") && !match($1,"inet6") && match($2,"addr")) {
            ipaddr=substr($2,6);
            maskaddr=substr($4,6);
            continue;
        }
    }    

    #system("echo sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;INSERT INTO '"${tablename}"' VALUES (\""ifname"\",\"1\",\""mac"\",\""substr(vlan,4)"\",\""ssid"\",\""ipaddr"\",\""maskaddr"\",\""chan"\",\""txpower"\",\""mode"\",\""bandwidth"\");COMMIT'\''");
    system("sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;INSERT INTO '"${tablename}"' VALUES (\""ifname"\",\"1\",\""mac"\",\""substr(vlan,4)"\",\""ssid"\",\""ipaddr"\",\""maskaddr"\",\""chan"\",\""txpower"\",\""mode"\",\""bandwidth"\");COMMIT'\''");

}

}'


         
rm -rf /tmp/ifaceinfo.lock


