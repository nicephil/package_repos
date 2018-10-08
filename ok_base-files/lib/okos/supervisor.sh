#!/bin/sh

while :
do
    sleep 30


    okos_mgr_pid=$(pgrep -f "/lib/okos/okos_mgr.py")
    okos_mgr_count=$(echo $_pid | awk '{print NF}')
    [ -z "$okos_mgr_pid" -o "$okos_mgr_count" -gt "1" ] && {
        logger -t supervisor -p 3 "OKOS_MGR ($okos_mgr_pid) is exit abnormally, restart it !!!"
        /etc/init.d/okos_mgrc restart
    }

    echo 3 > /proc/sys/vm/drop_caches
    top -n1 -d1 -b | logger -t supervisor -p 7
    ls -la /tmp | logger -t supervisor -p 7
    df -h | logger -t supervisor -p 7
done

