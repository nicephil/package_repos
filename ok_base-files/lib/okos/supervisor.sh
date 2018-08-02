#!/bin/sh

while :
do
    sleep 30


    capwap_pid=$(pgrep -f "/usr/sbin/ok_capwapc")
    capwap_count=$(echo $capwap_pid | awk '{print NF}')
    [ -z "$capwap_pid" -o "$capwap_count" -gt "1" ] && {
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
        rm -rf /tmp/wifievent.pipe;ulimit -c unlimited;nice -n -20 /lib/okos/clientevent.py
    }

    for ath in `ls /var/run/hostapd-wifi0 2>/dev/null` `ls /var/run/hostapd-wifi1 2>/dev/null`
    do
        hostapd_cli_pid=`pgrep -f "hostapd_cli.*${ath}.*"`
        hostapd_cli_count=$(echo $hostapd_cli_pid | awk '{print NF}')
        [ -z "$hostapd_cli_pid" -o "$hostapd_cli_count" -gt "1" ] && {
            if [ -n "$hostapd_cli_pid" ]
            then
                for _pid in $hostapd_cli_pid
                do
                    kill -9 $_pid
                done
            fi
            logger -t supervisor -p 3 "HOSTAPD_CLI ($hostapd_cli_pid) is exit abnormally, restart it !!!"
            wifi_index=${ath:3:1}
            if [ "${wifi_index}" = "5" ]
            then
                wifi_index="0"
            elif [ "${wifi_index}" = "6" ]
            then
                wifi_index="1"
            fi
            ulimit -c unlimited;nice -n -20 hostapd_cli -P /var/run/hostapd_cli-${ath}.pid -p /var/run/hostapd-wifi${wifi_index} -i $ath -a /lib/okos/wifievent.sh  2>&1 | logger -t 'hostapd_cli' &
        }
    done
    top -n1 -d1 -b | logger -t supervisor -p 7
    ls -la /tmp | logger -t supervisor -p 7
    df -h | logger -t supervisor -p 7
done

