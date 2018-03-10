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

{
touch $lockfile

/etc/init.d/cron stop
killall apstats iwconfig ifconfig

/etc/init.d/network reload
sync;echo 3 > /proc/sys/vm/drop_caches
sleep 15
/etc/init.d/wifidog restart &
/etc/init.d/qos restart &
/etc/init.d/arpwatch restart&
/etc/init.d/apfw.dyn restart&
/etc/init.d/cron start&

rm -rf $lockfile
}&

