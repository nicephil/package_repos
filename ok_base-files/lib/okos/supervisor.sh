#!/bin/sh

while :
do
    sleep 30


    capwap_pid=$(pgrep -f "/usr/sbin/ok_capwapc")
    capwap_count=$(echo $capwap_pid | awk '{print NF}')
    [ -z "$capwap_pid" -o "$capwap_count" -gt "1" ] && {
        logger -t supervisor -p 5 "CAPWAP is exit abnormally, restart it !!!"
        /etc/init.d/capwapc restart
    }

    wifidog_pid=$(pgrep -f "/usr/bin/wifidog -s -d")
    wifidog_count=$(echo $wifidog_pid | awk '{print NF}')
    [ -z "$wifidog_pid" -o "$wifidog_count" -gt "1" ] && {
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

    [ -z "`pgrep -f 'hostapd '`" ] && {
        /etc/init.d/hostapd restart
    }

    for ath in `ls /var/run/hostapd-wifi0 2>/dev/null` `ls /var/run/hostapd-wifi1 2>/dev/null`
    do
        pid=`pgrep -f "hostapd_cli.*${ath}.*"`
        [ -z "$pid" ] && {
            logger -t supervisor -p 5 "HOSTAPD_CLI is exit abnormally, restart it !!!"
            ulimit -c unlimited;nice -n -20 hostapd_cli -P /var/run/hostapd_cli-${ath}.pid -p /var/run/hostapd-wifi${ath:3:1} -i $ath -a /lib/okos/wifievent.sh  2>&1 | logger -t 'hostapd_cli' &
        }
    done
    top -n1 -d1 -b | logger -t supervisor -p 7
    ls -la /tmp | logger -t supervisor -p 7
    df -h | logger -t supervisor -p 7
done

