#!/bin/sh

mac=$1
l_time=$2
action=$3 # 1 means set, 0 means unset
mode=$4
[ -z "$mac" -o -z "$mode" -o -z "$l_time" -o -z "$action" -o -z "$mode" ] && {
    logger -t clientevent -p 3 "xxsetwhitelist:mac:$mac, l_time:$l_time, action:$action, mode:$mode"
    exit 1
}

logger -t clientevent -p 3 "++setwhitelist:mac:$mac, l_time:$l_time, action:$action, mode:$mode"

atjobs_dir="/var/spool/cron/atjobs"

. /lib/okos/whitelist.sh

if [ "$mode" = "0" ]
then
# whitelist
if [ "$action" = "1" ]
then

    # 1. del it from blacklist
    iwconfig 2>/dev/null | awk '/ath/{system("iwpriv "$1" delmac '"$mac"'");}'

    # 2. del it from blacklist timer
    # 3. del it from whitelist timer
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

    # 4. add it into whitelist timer
    if [ "$l_time" -ne "0" ]
    then
        echo ". /lib/okos/whitelist.sh start;del_from_whitelist $mac" | at now +$((l_time/60))minutes
    fi

    # 5. add it into whitelist
    logger -t clientevent "setwhitelist:add_mac:$mac"
    add_to_whitelist $mac
fi

if [ "$action" = "0" ]
then
    # 1. del it from whitelist
    logger -t clientevent "setwhitelist:del_mac:$mac"
    del_from_whitelist $mac

    # 2. del it from whitelist timer
    for file in $(ls $atjobs_dir)
    do
        grep -q "del_from_whitelist $mac" ${atjobs_dir}/${file}
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

else

# gotoportal
if [ "$action" = "1" ]
then
    logger -t clientevent "setwhitelist:add_gotoportal:$mac"
    add_to_gotoportal $mac
else
    logger -t clientevent "setwhitelist:del_gotoportal:$mac"
    del_from_gotoportal $mac
fi

fi
logger -p 3 -t clientevent "--setwhitelist:mac:$mac, l_time:$l_time, action:$action, mode:$mode"
