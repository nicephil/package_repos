#!/bin/sh

while :
do
    sleep 30
    [ -z "`pgrep -f capwapc`" ] && {
        logger -t supervisor -p 5 "CAPWAP is exit abnormally, restart it !!!"
        /etc/init.d/capwapc restart
    }
    [ -z "`pgrep -f wifidog`" ] && {
        logger -t supervisor -p 5 "WIFIDog is exit abnormally, restart it !!!"
        /etc/init.d/wifidog restart
    }
    [ -z "`pgrep -f clientevent.py`" ] && {
        logger -t supervisor -p 5 "CLIENTEVENT is exit abnormally, restart it !!!"
        killall -9 clientevent.py
        rm -rf /tmp/wifievent.pipe
        /lib/okos/clientevent.py
    }
done

