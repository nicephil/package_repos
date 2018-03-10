#!/bin/sh

lockfile="/tmp/restartservices.lock"

if [ -f "$lockfile" ]
then
    return 1
fi

touch $lockfile

/etc/init.d/network restart
sync;echo 3 > /proc/sys/vm/drop_caches
sleep 25
/etc/init.d/wifidog restart &
/etc/init.d/qos restart &
/etc/init.d/arpwatch restart&
/etc/init.d/apfw.dyn restart&

rm -rf $lockfile

