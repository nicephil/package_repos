#!/bin/sh


ath=$1
st="ServiceTemplate""${ath:4}"
rd="${ath:3:1}"
echo -e "\toption radioid "$rd

bssid=`ifconfig ath12 | awk '$1 ~ /ath/{print $5;exit 0;}'`
echo -e "\toption bssid "$bssid

. /lib/functions.sh






config_load wlan_service_template
config_get _auth $st authentication
echo -e "\toption authentication "$_auth
config_get _ps $st portal_scheme
echo -e "\toption portal_scheme "$_ps
config_get _ssid $st ssid
echo -e "\toption ssid "$_ssid

config_load wireless
config_get _vlan $ath network
echo -e "\toption vlan "${_vlan:3}


