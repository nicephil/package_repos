#!/bin/sh

# 1. generate new apstats log
rm -rf /tmp/apstats_*[!_prev].log
apstats -a -R > /tmp/apstats_`date +%s`.log 2>/dev/null
file_name=`ls /tmp/apstats_*[!_prev].log 2>/dev/null`
# exit if no log file
if [ -z "$file_name" ]
then
    exit
fi
timestamp=`echo $file_name | awk -F'[_\.]' '{print $2}'`

# 2. check the prev apstas log
file_name_prev=`ls /tmp/apstats_*_prev.log 2>/dev/null`
if [ -z "$file_name_prev" ]
then
    rm -rf /tmp/apstats_*_prev.log
    mv "$file_name" /tmp/apstats_${timestamp}_prev.log
    exit
fi
timestamp_prev=`echo $file_name_prev | awk -F'[_\.]' '{print $2}'`


# 3. read config
. /lib/functions.sh
config_load productinfo
config_get mac productinfo mac
if [ -z "$mac" ]
then
    exit
fi
mac=`echo $mac|tr -d ':'`
config_load capwapc
config_get mas_server server mas_server
if [ -z "$mas_server" ]
then
    exit
fi
config_load wireless


format_output ()
{
    local file_name="$1"
    local output_type="$2"
    case "$output_type" in
    "VAP" )
        awk -F'[ =]+' 'BEGIN {OFS="|"} /VAP Level Stats/{
            vap=$4;
            radio=substr($7,1,length($7)-1);

            while (getline > 0 && length($0) > 0) {
                if (match($1$2$3,"TxDataBytes")) {
                    txB=$4;
                } else if (match($1$2$3,"RxDataBytes")) {
                    rxB=$4
                }
            }

            print vap,radio,txB,rxB

        }' ${file_name}
    ;;
    "WLAN" )
        awk -F'[ =]+' 'BEGIN {OFS="|"} /WLAN Stats/{

            while (getline > 0 && length($0) > 0) {
                if (match($1$2$3,"TxDataBytes")) {
                    txB=$4;
                } else if (match($1$2$3,"RxDataBytes")) {
                    rxB=$4
                }
            }

            print "WLAN",txB,rxB

        }' ${file_name}
    ;;
    * )
    ;;
    esac
}


# 4. generate json file
. /usr/share/libubox/jshn.sh
json_init
json_add_string "mac" "`echo ${mac} | sed 's/://g'`"
json_add_int "timestamp" "$timestamp_prev"

# 4.1 Add WLAN
# fetch WLAN Stats
wlan_data_cur=`format_output $file_name "WLAN"`
wlan_data_prev=`format_output $file_name_prev "WLAN"`
OIFS=$IFS; IFS="|"; set -- $wlan_data_cur; txB=$2;rxB=$3; IFS=$OIFS
# echo "--------->"$txB $rxB
OIFS=$IFS; IFS="|"; set -- $wlan_data_prev; txB_prev=$2;rxB_prev=$3; IFS=$OIFS
# echo "--------->"$txB_prev $rxB_prev
if [ "$txB" -ge "$txB_prev" -a "$rxB" -ge "$rxB_prev" ]
then
    Delta_txB=$((txB - txB_prev))
    Delta_rxB=$((rxB - rxB_prev))
else
    Delta_txB="$txB"
    Delta_rxB="$rxB"
fi
# echo "+++++>"WLAN", $Delta_txB, $Delta_rxB"

json_add_object "WLAN"
json_add_int "Tx_Data_Bytes" "$Delta_rxB"
json_add_int "Rx_Data_Bytes" "$Delta_txB"
json_close_object


# 4.2 Add VAP
json_add_array "VAP_Stats"

# 5. fetch VAP Level Stats from cur log
datas_cur=`format_output $file_name "VAP"`

# 6. fetch VAP Level Stats from prev log
datas_prev=`format_output $file_name_prev "VAP"`

# 7. calculate delta
for data_cur in `echo $datas_cur`
do
    OIFS=$IFS; IFS="|"; set -- $data_cur; ath=$1;radio=$2;txB=$3;rxB=$4; IFS=$OIFS
    # echo "--------->"$ath $radio $txB $rxB
    if [ "$ath" = "ath50" ]
    then
        continue
    fi
    for data_prev in `echo $datas_prev`
    do
        OIFS=$IFS; IFS="|"; set -- $data_prev; ath_prev=$1;radio_prev=$2;txB_prev=$3;rxB_prev=$4; IFS=$OIFS
        if [ "$ath" = "$ath_prev" ]
        then
            # echo "==========>"$ath_prev $radio_prev $txB_prev $rxB_prev
            if [ "$txB" -ge "$txB_prev" -a "$rxB" -ge "$rxB_prev" ]
            then
                Delta_txB=$((txB - txB_prev))
                Delta_rxB=$((rxB - rxB_prev))
            else
                Delta_txB="$txB"
                Delta_rxB="$rxB"
            fi
            # echo "+++++>$ath, $Delta_txB, $Delta_rxB"
            json_add_object "VAP" "$ath"
            json_add_string "VAP" "$ath"
            json_add_string "radio" "$radio"
            config_get ssid "$ath" "ssid"
            json_add_string "ssid" "$ssid"
            json_add_int "Tx_Data_Bytes" "$Delta_rxB"
            json_add_int "Rx_Data_Bytes" "$Delta_txB"
            json_close_object
            break
        fi
    done
done

json_close_array

rm -rf /tmp/apstats_*_prev.log
mv ${file_name} /tmp/apstats_${timestamp}_prev.log

# 8. generate .json
rm -rf /tmp/apstats_*.json
json_file=apstats_${mac}_${timestamp_prev}.json
json_dump 2>/dev/null | tee /tmp/${json_file}


if [ ! -e "/tmp/$json_file" ]
then
    exit
fi

# 10. upload json file to nms
URL="http://${mas_server}/nms/file/device/stat?objectname=${json_file}&override=1"
curl -s -F "action=upload" -F "filename=@/tmp/${json_file}"  "$URL"
