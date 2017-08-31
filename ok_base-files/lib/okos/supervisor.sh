#!/bin/sh

while :
do
    sleep 30

    [ -z "`pgrep -f capwapc`" ] && {
        logger -t supervisor -p 5 "CAPWAP is exit abnormally, restart it !!!"
        /etc/init.d/capwapc restart
    }

    ps w | logger -t supervisor -p 7
    top -n 1 | logger -t supervisor -p 7
    ls -la /tmp | logger -t supervisor -p 7
    df | logger -t supervisor -p 7
done

