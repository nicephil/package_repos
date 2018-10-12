#!/bin/sh

while :
do
    sleep 30

    echo 3 > /proc/sys/vm/drop_caches
    top -n1 -d1 -b | logger -t supervisor -p 7
    ls -la /tmp | logger -t supervisor -p 7
    df -h | logger -t supervisor -p 7
    ps w | logger -t supervisor -p 7

    capwap_pid=$(pgrep -f "/usr/sbin/ok_capwapc")
    capwap_count=$(echo $capwap_pid | awk '{print NF}')
    [ -z "$capwap_pid" -o "$capwap_count" -gt "1" ] && {
        [ "$capwap_count" -eq "2" ] && {
            kill -9 $(pgrep -n -f "/usr/sbin/ok_capwapc")
        }
        logger -t supervisor -p 3 "CAPWAP ($capwap_pid) is exit abnormally, restart it !!!"
        /etc/init.d/capwapc restart
    }

    wifidog_pid=$(pgrep -f "/usr/bin/wifidog -s -d")
    wifidog_count=$(echo $wifidog_pid | awk '{print NF}')
    [ -z "$wifidog_pid" -o "$wifidog_count" -gt "1" ] && {
        logger -t supervisor -p 3 "WIFIDog ($wifidog_pid)is exit abnormally, restart it !!!"
        /etc/init.d/wifidog restart
    }

    dnsmasq_pid=$(pgrep -f "/usr/sbin/dnsmasq -C /var/etc/dnsmasq.conf")
    dnsmasq_count=$(echo $dnsmasq_pid | awk '{print NF}')
    [ -z "$dnsmasq_pid" -o "$dnsmasq_count" -gt "1" ] && {
        logger -t supervisor -p 3 "dnsmasq ($dnsmasq_pid)is exit abnormally, restart it !!!"
        /etc/init.d/dnsmasq restart
    }

    clientevent_pid=$(pgrep -f "/lib/okos/clientevent.py")
    clientevent_count=$(echo $clientevent_pid | awk '{print NF}')
    [ -z "$clientevent_pid" -o "$clientevent_count" -gt "1" ] && {
        logger -t supervisor -p 3 "CLIENTEVENT ($clientevent_pid) is exit abnormally, restart it !!!"
        killall -9 clientevent.py
        killall -9 wifievent.sh
        rm -rf /tmp/wifievent.pipe;ulimit -c unlimited;nice -n -15 /lib/okos/clientevent.py
    }

    hostapd_pid=$(pgrep -f "hostapd -g /var/run/hostapd/global")
    hostapd_count=$(echo $hostapd_pid | awk '{print NF}')
    [ -z "$hostapd_pid" -o "$hostapd_count" -gt "1" ] && {
        logger -t supervisor -p 3 "hostapd ($hostapd_pid) is exit abnormally, restart it !!!"
        [ -n "$hostapd_pid" ] && kill -9  $hostapd_pid
	    ulimit -c unlimited;nice -n -15 hostapd -g /var/run/hostapd/global -B -P /var/run/hostapd-global.pid
    }
    hostapd_cli_pid=$(pgrep -f "hostapd_cli -B")
    hostapd_cli_count=$(echo $hostapd_cli_pid | awk '{print NF}')
    [ -z "$hostapd_cli_pid" -o "$hostapd_cli_count" -gt "1" ] && {
        logger -t supervisor -p 3 "hostapd_cli ($hostapd_cli_pid) is exit abnormally, restart it !!!"
        [ -n "$hostapd_cli_pid" ] && kill -9  $hostapd_cli_pid
	    ulimit -c unlimited;nice -n -15 hostapd_cli -B -a /lib/okos/wifievent.sh
    }

done

