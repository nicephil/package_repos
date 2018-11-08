#!/bin/sh


# 0. generate productinfo
/lib/okos/fetch_productinfo.sh > /etc/config/productinfo

# 1. sethostname
mac=`uci get productinfo.productinfo.mac | tr -d : | tr '[a-z]' '[A-Z]'`
uci set system.@system[0].hostname="$mac";uci commit system
hostname "$mac"
echo "$mac" > /proc/sys/kernel/hostname

# 2. sync config from sysloader
#[ -f "/overlay/etc/config/capwapc" ] && cp /overlay/etc/config/capwapc /etc/config/capwapc

# 3. init db
dbfile="/tmp/stationinfo.db"
tablename="STAINFO"
rm -rf $dbfile
#echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(PPPD_PID TEXT PRIMARY KEY NOT NULL,IFNAME,DEVICE,IPLOCAL,IPREMOTE,PEERNAME,TS,TX,RX,PEER_PUBIP);COMMIT;"
sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(PPPD_PID TEXT PRIMARY KEY NOT NULL,IFNAME,DEVICE,IPLOCAL,IPREMOTE,PEERNAME,TS,TX,RX,PEER_PUBIP);COMMIT;"
