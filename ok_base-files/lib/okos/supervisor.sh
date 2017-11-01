#!/bin/sh

while :
do
    sleep 30

    cat /etc/config/dhcp | grep "/#/172.16.254.254" >/dev/null 2>&1
    if [ "$?" = "0" ]
    then
        ping -c1 -W5 8.8.8.8 >/dev/null 2>&1
        ret1="$?"
        ping -c1 -W5 114.114.114.114 >/dev/null 2>&1
        ret2="$?"
        if [ "$ret1" = "0" -o "$ret2" = "0" ] 
        then
            uci del_list dhcp.@dnsmasq[0].address='/#/172.16.254.254';uci commit dhcp;/etc/init.d/dnsmasq restart;
        fi
    fi

    [ -z "`pgrep -f capwapc`" ] && {
        logger -t supervisor -p 5 "CAPWAP is exit abnormally, restart it !!!"
        /etc/init.d/capwapc restart
    }

    ps w | logger -t supervisor -p 7
    top -n 1 | logger -t supervisor -p 7
    ls -la /tmp | logger -t supervisor -p 7
    df | logger -t supervisor -p 7
done

