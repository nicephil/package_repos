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

#CREATE TABLE IFINFO(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH,LINKSTATUS);
# echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH,LINKSTATUS);COMMIT;" 
sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH,LINKSTATUS);COMMIT;" 
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
    linkstatus=""
    config_get _disabled $ifname disabled
    config_get mac $ifname macaddr
    [ "$_disabled" = "1" ] && { 
        state="0"
        #echo sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\",\"$linkstatus\");COMMIT"
        sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\",\"$linkstatus\");COMMIT"
        [ "$has_reportnow" = "1" ] && {
            echo "radio $i turned off by configure" | logger -p user.info -t '01-SYSTEM-LOG'
        }
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
    txpower=$(iwconfig $vifname | awk  '/Tx-Power/{txpower=substr($4,10);print txpower;exit}')
    mode=$(iwpriv $vifname get_mode | awk -F':' '{print substr($2,1,4);exit}' | tr '[A-Z]' '[a-z]')
    bandwidth=HT$(iwpriv $vifname get_mode | awk '{print substr($2,length($2)-1,3);exit}')
    if [ "$i" = "0" ]
    then
        export "chan_2=$chan"
        export "txpower_2=$txpower"
        export "mode_2=$mode"
        export "bandwidth_2=$bandwidth"
    elif [ "$i" = "1" ]
    then
        export "chan_5=$chan"
        export "txpower_5=$txpower"
        export "mode_5=$mode"
        export "bandwidth_5=$bandwidth"
    fi

    
    #echo "ifname:$ifname,state:$state,mac:$mac,vlan:$vlan,ssid:$ssid,ipaddr:$ipaddr,maskaddr:$maskaddr,chan:$chan,txpower:$txpoer,mode:$mode,bandwidth:$bandwidth,linkstatus:$linkstatus" | logger -p user.info -t '01-SYSTEM-LOG'
    [ "$has_reportnow" = "1" ] && {
        echo "radio $i is up, ch$chan, ${txpower}dbm, $mode, $bandwidth" | logger -p user.info -t "01-SYSTEM-LOG"
    }
        
    #echo sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\",\"$linkstatus\");COMMIT"
    # echo "--->$vifname, $txpower, $mode, $bandwidth"
    sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"$ifname\",\"$state\",\"$mac\",\"$vlan\",\"$ssid\",\"$ipaddr\",\"$maskaddr\",\"$chan\",\"$txpower\",\"$mode\",\"$bandwidth\",\"$linkstatus\");COMMIT"

done
 

iwconfig 2> /dev/null | awk '{
                              
if (match($1,"ath") && !match($1, "ath50") && !match($1, "ath60")) {        
    ifname=mac=vlan=ssid=ipaddr=maskaddr=chan=txpower=mode=bandwidth=linkstatus="";
    radio_index=substr($1,4,1)
    "(. /lib/functions.sh;config_load wireless;config_get  _vlan "$1" network;echo $_vlan;)" | getline vlan
    if (match(radio_index, "0")) {
        chan=ENVIRON["chan_2"];
        txpower=ENVIRON["txpower_2"];
        mode=ENVIRON["mode_2"];
        bandwidth=ENVIRON["bandwidth_2"];
    } else {
        chan=ENVIRON["chan_5"];
        txpower=ENVIRON["txpower_5"];
        mode=ENVIRON["mode_5"];
        bandwidth=ENVIRON["bandwidth_5"];
    }
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

    #system("echo sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;INSERT INTO '"${tablename}"' VALUES (\""ifname"\",\"1\",\""mac"\",\""substr(vlan,4)"\",\""ssid"\",\""ipaddr"\",\""maskaddr"\",\""chan"\",\""txpower"\",\""mode"\",\""bandwidth"\",\""linkstatus"\");COMMIT'\''");
    system("sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;INSERT INTO '"${tablename}"' VALUES (\""ifname"\",\"1\",\""mac"\",\""substr(vlan,4)"\",\""ssid"\",\""ipaddr"\",\""maskaddr"\",\""chan"\",\""txpower"\",\""mode"\",\""bandwidth"\",\""linkstatus"\");COMMIT'\''");
    if (chan && txpower) {
        #system("echo sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;UPDATE '"${tablename}"' SET CHAN=\""chan"\",TXPOWER=\""txpower"\" WHERE IFNAME=\"wifi"radio_index"\";COMMIT'\''");
        system("sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;UPDATE '"${tablename}"' SET CHAN=\""chan"\",TXPOWER=\""txpower"\" WHERE IFNAME=\"wifi"radio_index"\";COMMIT'\''");
    }
}

}'

ifconfig 2> /dev/null | awk '{
                              
if (match($1,"eth") || match($1,"br-lan")) {
    ifname=mac=vlan=ssid=ipaddr=maskaddr=chan=txpower=mode=bandwidth=linkstatus="";
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

    #system("echo sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;INSERT INTO '"${tablename}"' VALUES (\""ifname"\",\"1\",\""mac"\",\""substr(vlan,4)"\",\""ssid"\",\""ipaddr"\",\""maskaddr"\",\""chan"\",\""txpower"\",\""mode"\",\""bandwidth"\",\""linkstatus"\");COMMIT'\''");
    system("sqlite3 '"$dbfile"' '\''BEGIN TRANSACTION;INSERT INTO '"${tablename}"' VALUES (\""ifname"\",\"1\",\""mac"\",\""substr(vlan,4)"\",\""ssid"\",\""ipaddr"\",\""maskaddr"\",\""chan"\",\""txpower"\",\""mode"\",\""bandwidth"\",\""linkstatus"\");COMMIT'\''");

}

}'

eth0_state=0
if [ "$(swconfig dev switch0 show | awk -F '[: ]+' '/pvid: 1/{getline;print $5}')" = "up" ]
then
    eth0_state=1
fi
eth0_linkstatus=$(swconfig dev switch0 show | awk -F '[: ]+' '/pvid: 1/{getline;print $7,$8}')
eth0_mac=$(cat /sys/class/net/eth0/address)
eth0_ipaddr=$(ifconfig br-lan1 | awk -F'[ :]+' '/inet addr/{print $4}')
eth0_maskaddr=$(ifconfig br-lan1 | awk -F'[ :]+' '/Mask/{print $8}')
sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"eth0\",\"$eth0_state\",\"$eth0_mac\",\"1\",\"\",\"$eth0_ipaddr\",\"$eth0_maskaddr\",\"\",\"\",\"\",\"\",\"$eth0_linkstatus\");COMMIT"


eth1_state=0
if [ "$(swconfig dev switch0 show | awk -F '[: ]+' '/pvid: 4090/{getline;print $5}')" = "up" ]
then
    eth1_state=1
fi
eth1_linkstatus=$(swconfig dev switch0 show | awk -F '[: ]+' '/pvid: 4090/{getline;print $7,$8}')
eth1_mac=$(cat /sys/class/net/eth0.4090/address)
sqlite3 $dbfile "BEGIN TRANSACTION;INSERT INTO ${tablename} VALUES (\"eth1\",\"$eth1_state\",\"$eth1_mac\",\"$eth1_state\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"$eth1_linkstatus\");COMMIT"


         
rm -rf /tmp/ifaceinfo.lock
return 0
