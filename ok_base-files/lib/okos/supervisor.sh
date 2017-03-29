#!/bin/sh

while :
do
    if [ -n "`pgrep capwapc`" ]
    then
        sleep 30
    else
        logger -p 5 "CAPWAP is exist abnormally, restart it !!!"
        /etc/init.d/capwapc restart
    fi
done

