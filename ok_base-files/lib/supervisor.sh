#!/bin/sh

while :
do
    ps w > /tmp/ps.log
    grep "capwapc" /tmp/ps.log
    if [[ $? -eq 0 ]]
    then
        sleep 30
    else
        /etc/init.d/capwapc restart
        logger "CAPWAP is exist abnormally, restart it !!!"
    fi
done

