#!/bin/sh

mac=$1
time=$2
action=$3 # 1 means set, 0 means unset

atjobs_dir="/var/spool/cron/atjobs"

if [ "$action" = "1" ]
then


    # 1. del it from whitelist


    # 2. del it from whitelist timer
    # 3. del it from blacklist timer
    for file in $(ls $atjobs_dir)
    do
        grep -q "$mac" ${atjobs_dir}/${file}
        if [ "$?" -eq "0" ]
        then
            if [ ${file:0:1} = "=" ]
            then
                sleep 20
            else
                echo "cancel exising timer"
                rm -rf ${atjobs_dir}/${file}
            fi
        fi
    done 



    # 4. add it into blacklist timer
    echo "iwconfig 2>/dev/null | awk '/ath/{system(\"iwpriv \"\$1\" delmac $mac\");}'" | at now +$((time/60))minutes

    # 5. add it into blacklist
    iwconfig 2>/dev/null | awk '/ath/{system("iwpriv "$1" addmac '"$mac"'");}'

    exit 0
fi

if [ "$action" = "0" ]
then
    # 1. del it from blacklist
    iwconfig 2>/dev/null | awk '/ath/{system("iwpriv "$1" delmac '"$mac"'");}'
    # 2. del it from blacklist timer
    for file in $(ls $atjobs_dir)
    do
        grep -q "$mac" ${atjobs_dir}/${file}
        if [ "$?" -eq "0" ]
        then
            if [ ${file:0:1} = "=" ]
            then
                sleep 20
            else
                echo "cancel exising timer"
                rm -rf ${atjobs_dir}/${file}
            fi
        fi
    done 
fi
