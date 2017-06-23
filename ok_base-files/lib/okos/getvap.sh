#!/bin/sh

. /lib/functions.sh
config_load wireless

. /usr/share/libubox/jshn.sh
json_init

# VAP_Stats
json_add_array "VAP_Stats"

for ath in `iwconfig 2>/dev/null | awk '/ath/{print $1}'`
do
    echo "---->ath:$ath"
    # 0. skip debug ath
    if [ "$ath" = "ath50" ]
    then
        continue
    fi
    
    # 1. fetch apstats log
    rm -rf /tmp/apstats_${ath}_*[!_prev].log
    apstats -v -i $ath > /tmp/apstats_${ath}_`date +%s`.log
    file_name=`ls /tmp/apstats_${ath}_*[!_prev].log 2>/dev/null`
    # continue if no log file
    if [ -z "$file_name" ] 
    then
        continue
    fi
    timestamp=`echo $file_name | awk -F'[_\.]' '{print $3}'`
    Tx_Data_Bytes=`awk -F'= ' '/Tx Data Bytes/{print $2; exit;}' $file_name`
    Rx_Data_Bytes=`awk -F'= ' '/Rx Data Bytes/{print $2; exit;}' $file_name`
    echo "===->file_name:$file_name timestamp:$timestamp Tx_Data_Bytes:$Tx_Data_Bytes Rx_Data_Bytes:$Rx_Data_Bytes"
    # contine if no valid content
    if [ -z "$timestamp" -o -z "$Tx_Data_Bytes" -o -z "$Rx_Data_Bytes" ]
    then
        continue
    fi
    
    # 2. fetch prev log 
    file_name_prev=`ls /tmp/apstats_${ath}_*_prev.log 2>/dev/null`
    if [ -z "$file_name_prev" ]
    then
        mv /tmp/apstats_${ath}_${timestamp}.log /tmp/apstats_${ath}_${timestamp}_prev.log
        continue
    fi
    timestamp_prev=`echo $file_name_prev | awk -F'[_\.]' '{print $3}'`
    Tx_Data_Bytes_prev=`awk -F'= ' '/Tx Data Bytes/{print $2; exit;}' $file_name_prev`
    Rx_Data_Bytes_prev=`awk -F'= ' '/Rx Data Bytes/{print $2; exit;}' $file_name_prev`
    echo "===+>file_name_prev:$file_name_prev timestamp_prev:$timestamp_prev Tx_Data_Bytes_prev:$Tx_Data_Bytes_prev Rx_Data_Bytes_prev:$Rx_Data_Bytes_prev"
    if [ -z "$timestamp_prev" -o -z "$Tx_Data_Bytes_prev" -o -z "$Rx_Data_Bytes_prev" ]
    then
        rm -rf /tmp/apstats_${ath}_*_prev.log
        mv /tmp/apstats_${ath}_${timestamp}.log /tmp/apstats_${ath}_${timestamp}_prev.log
        continue
    fi
    # 2.1 valid prev log is existing
    if [ "$Tx_Data_Bytes" -ge "$Tx_Data_Bytes_prev" -a "$Rx_Data_Bytes" -ge "$Rx_Data_Bytes_prev" ]
    then
        Delta_Tx_Data_Bytes=$(($Tx_Data_Bytes - $Tx_Data_Bytes_prev))
        Delta_Rx_Data_Bytes=$(($Rx_Data_Bytes - $Rx_Data_Bytes_prev))
    else
        Delta_Tx_Data_Bytes="$Tx_Data_Bytes"
        Delta_Rx_Data_Bytes="$Rx_Data_Bytes"
    fi
    echo "====$>Delta_Tx_Data_Bytes:$Delta_Tx_Data_Bytes Delta_Rx_Data_Bytes:$Delta_Rx_Data_Bytes"
    
    radioid=${ath:3:1}
    config_get ssid $ath ssid
    
    # $ath
    json_add_object "$ath"
    
    json_add_string "radio" "wifi${radioid}"
    json_add_string "ssid" "$ssid"
    json_add_int "Tx_Data_Bytes" "$Delta_Tx_Data_Bytes"
    json_add_int "Rx_Data_Bytes" "$Delta_Rx_Data_Bytes"
    
    json_close_object
    
done

json_close_array

json_dump

