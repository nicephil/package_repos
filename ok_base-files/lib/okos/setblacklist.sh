#!/bin/sh

mac=$1
l_time=$2
action=$3 # 1 means set, 0 means unset
ath=$4
l_time=240

[ -z "$mac" -o -z "$l_time" -o -z "$action" -o -z "$ath" ] && {
    logger -t clientevent -p 3 "xxsetblacklist:mac:$mac, l_time:$L_time, action:$action, ath:$ath"
    exit 1
}


logger -t clientevent -p 3 "++setblacklist:mac:$mac, l_time:$l_time, action:$action, ath:$ath"

atjobs_dir="/var/spool/cron/atjobs"

. /lib/okos/whitelist.sh

if [ "$action" = "1" ]
then


    # 1. del it from whitelist
    del $mac

    # 2. del it from whitelist timer
    # 3. del it from blacklist timer
    for file in $(ls $atjobs_dir)
    do
        grep -q "$mac" ${atjobs_dir}/${file}
        if [ "$?" -eq "0" ]
        then
            if [ "${file:0:1}" = "=" ]
            then
                sleep 20
            else
                echo "cancel existing timer ${file}"
                rm -rf ${atjobs_dir}/${file}
            fi
        fi
    done 

    # 4. add it into blacklist timer
    echo "iwpriv $ath delmac $mac" | at now +$((l_time/60))minutes

    # 5. add it into blacklist
    iwpriv "$ath" addmac "$mac"

    # 6. kickoff it
    iwpriv "$ath" kickmac "$mac"

fi

if [ "$action" = "0" ]
then
    # 1. del it from blacklist
    iwconfig 2>/dev/null | awk '/ath/{system("iwpriv "$1" delmac '"$mac"'");}'
    # 2. del it from blacklist timer
    for file in $(ls $atjobs_dir)
    do
        grep -q "delmac $mac" ${atjobs_dir}/${file}
        if [ "$?" -eq "0" ]
        then
            if [ ! "${file:0:1}" = "=" ]
            then
                echo "cancel existing timer ${file}"
                rm -rf ${atjobs_dir}/${file}
            fi
        fi
    done 
fi

echo "--setblacklist:mac:$mac, l_time:$l_time, action:$action" | logger -t clientevent -p 3
