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
        killall wifievent.sh
        rm -rf /tmp/wifievent.pipe
        /lib/okos/clientevent.py
    }

    for ath in `ls /var/run/hostapd-wifi0 2>/dev/null` `ls /var/run/hostapd-wifi1 2>/dev/null`
    do
        pid=`pgrep -f "hostapd_cli.*${ath}.*"`
        [ -z "$pid" ] && {
            logger -t supervisor -p 5 "HOSTAPD_CLI is exit abnormally, restart it !!!"
            nice -n -20 hostapd_cli -p /var/run/hostapd-wifi${ath:3:1} -i $ath -a /lib/wifi/wifievent.sh -B
        }
    done
    ps w | logger -t supervisor -p 7
    top -n 1 | logger -t supervisor -p 7
    ls -la /tmp | logger -t supervisor -p 7
    df | logger -t supervisor -p 7
done

