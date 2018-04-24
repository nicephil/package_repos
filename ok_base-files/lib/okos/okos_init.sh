### invoked from /etc/init.d/boot during /etc/init.d/boot start
#!/bin/sh

# 1. global db initialization
dbfile="/tmp/stationinfo.db"
tablename="STAINFO"
#echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_HMODE,PORTAL_USER,HOSTNAME,PPSK_KEY,REMAIN_TIME,PORTAL_STATUS);COMMIT;" | logger
sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(MAC TEXT PRIMARY KEY NOT NULL,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,HOSTNAME,PPSK_KEY,REMAIN_TIME,PORTAL_STATUS);COMMIT;"

dbfile="/tmp/ifaceinfo.db"
tablename="IFINFO"
#CREATE TABLE IFINFO(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);
# echo sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);COMMIT;" 
sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);COMMIT;"
sqlite3 $dbfile "BEGIN TRANSACTION;DELETE FROM ${tablename};COMMIT;"

dbfile="/tmp/statsinfo.db"
tablename="STATSINFO"
#echo sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR,MINRSSI,MAXRSSI,PORTAL_STATUS);COMMIT;" | logger
sqlite3 $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(MAC TEXT PRIMARY KEY NOT NULL,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,PSMODE,WANTXB,WANRXB,GWADDR,MINRSSI,MAXRSSI,PORTAL_STATUS);COMMIT;"