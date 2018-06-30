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
[ -n "$(iwconfig ath60 2>/dev/null)" ] && ifconfig wifi1 down
[ -n "$(iwconfig ath50 2>/dev/null)" ] && ifconfig wifi0 down

sync;echo 3 > /proc/sys/vm/drop_caches
/etc/init.d/wifidog restart
/etc/init.d/qos restart
/etc/init.d/arpwatch restart
/etc/init.d/apfw.dyn restart
[ -n "$(iwconfig ath60 2>/dev/null)" ] && ifconfig wifi1 up
[ -n "$(iwconfig ath50 2>/dev/null)" ] && ifconfig wifi0 up

sleep 5

rm -rf $lockfile
if [ ! -f "/tmp/firstboot_report" ]
then
    has_reportnow=1 /lib/okos/getifaceinfo.sh
    echo "configuration loaded successfully" | logger -p user.info -t "01-SYSTEM-LOG"
    echo "system is up" | logger -p user.info -t "01-SYSTEM-LOG"
    touch /tmp/firstboot_report
fi



return 0
