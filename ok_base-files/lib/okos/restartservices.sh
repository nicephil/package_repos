#!/bin/sh

lockfile="/tmp/restartservices.lock"

restartservices_trap () {
    rm -rf $lockfile
}

trap 'restartservices_trap; exit' INT TERM ABRT QUIT ALRM

if [ -f "$lockfile" ]
then
    return 1
fi

touch $lockfile

# stop upstabycron
kill -9 $(pgrep -f '/lib/okos/upstabycron.sh')
rm -rf /tmp/upstabycron.lock
# stop apstats
kill -9 $(pgrep -f '/lib/okos/apstats.sh')
rm -rf /tmp/apstats.lock
# stop runtimefixup
kill -9 $(pgrep -f '/lib/okos/runtimefixup.sh')
rm -rf /tmp/runtimefixup.lock
# stop setgre
kill -9 $(pgrep -f '/lib/okos/setgre.sh')
rm -rf /tmp/setgre.lock
# stop wlanconfig apstats iwconfig
killall -9 wlanconfig
killall -9 apstats
killall -9 iwconfig

sleep 5

/etc/init.d/network restart

sleep 10

sync;echo 3 > /proc/sys/vm/drop_caches
/etc/init.d/wifidog restart
/etc/init.d/qos restart
/etc/init.d/apfw.dyn restart


rm -rf $lockfile
if [ ! -f "/tmp/firstboot_report" ]
then
    has_reportnow=1 /lib/okos/getifaceinfo.sh
    echo "configuration loaded successfully" | logger -p user.info -t "01-SYSTEM-LOG"
    echo "system is up" | logger -p user.info -t "01-SYSTEM-LOG"
    touch /tmp/firstboot_report
fi



return 0
