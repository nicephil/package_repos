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

/etc/init.d/network restart

sync;echo 3 > /proc/sys/vm/drop_caches
/etc/init.d/wifidog restart &
/etc/init.d/qos restart &
/etc/init.d/arpwatch restart&
/etc/init.d/apfw.dyn restart&
/etc/init.d/supervisor restart&

sleep 5

rm -rf $lockfile

return 0
