#!/bin/sh

while :
do
    sleep 30
    [ -z "`pgrep capwapc`" ] && {
        logger -p 5 "CAPWAP is exist abnormally, restart it !!!"
        /etc/init.d/capwapc restart
    }
    [ -z "`pgrep wifidog`" ] && {
        logger -p 5 "WIFIDog is exist abnormally, restart it !!!"
        /etc/init.d/wifidog restart
    }
done

