#!/bin/sh

# check if service is restarting
lockfile="/tmp/restartservices.lock"

if [ -f "$lockfile" ]
then
    sleep 20
fi

if [ -f /tmp/ifaceinfo.lock ]
then
    exit 0
fi

getifaceinfo_trap () {
    logger -t getifaceinfo "gets trap"
    rm -rf /tmp/ifaceinfo.lock
}

trap 'getifaceinfo_trap; exit' INT TERM ABRT QUIT ALRM

touch /tmp/ifaceinfo.lock




dbfile="/tmp/ifaceinfo.db"
tablename="IFINFO"

#CREATE TABLE IFINFO(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);
# echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);COMMIT;" 
sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);COMMIT;" 
sqlite3 $dbfile "BEGIN TRANSACTION;DELETE FROM ${tablename};COMMIT;"

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
    config_get mac $ifname macaddr
    [ "$_disabled" = "1" ] && { 
        state="0"
        #echo sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\");COMMIT"
        sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\");COMMIT"
        continue
    }

    vifname=""
    if [ "$i" = "0" ]
    then
        vifname="ath50"
    elif [ "$i" = "1" ]
    then
        vifname="ath60"
    fi

    chan=$(iwinfo $vifname info | awk -F '[: ]+' '/Channel/{print $5;exit}'); 
    if [ "$i" = "0" ]
    then
        export "chan_2=$chan"
    elif [ "$i" = "1" ]
    then
        export "chan_5=$chan"
    fi

    txpower=$(iwconfig $vifname | awk  '/Tx-Power/{txpower=substr($4,10);print txpower;exit}')
    mode=$(iwpriv $vifname get_mode | awk -F':' '{print substr($2,1,4);exit}' | tr '[A-Z]' '[a-z]')
    bandwidth=HT$(iwpriv $vifname get_mode | awk '{print substr($2,length($2)-1,3);exit}')
    
    echo "ifname:$ifname,state:$state,mac:$mac,vlan:$vlan,ssid:$ssid,ipaddr:$ipaddr,maskaddr:$maskaddr,chan:$chan,txpower:$txpoer,mode:$mode,bandwidth:$bandwidth" | logger -p user.info -t '01-SYSTEM-LOG'
        
    #echo sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\");COMMIT"
    # echo "--->$vifname, $txpower, $mode, $bandwidth"
    sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\");COMMIT"

done
 
rm -rf /tmp/ifaceinfo.lock
return 0

iwconfig 2> /dev/null | awk '{
                              
if (match($1,"ath") && !match($1, "ath50") && !match($1, "ath60")) {        
    ifname=mac=vlan=ssid=ipaddr=maskaddr=chan=txpower=mode=bandwidth="";
    radio_index=substr($1,4,1)
    "(. /lib/functions.sh;config_load wireless;config_get  _vlan "$1" network;echo $_vlan;)" | getline vlan
    if (match(radio_index, "0")) {
        chan=ENVIRON["chan_2"];
    } else {
        chan=ENVIRON["chan_5"];
    }
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


