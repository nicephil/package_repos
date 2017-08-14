#!/bin/sh

/etc/init.d/network restart
sync;echo 3 > /proc/sys/vm/drop_caches
sleep 15
rm -rf /tmp/qos.lock
rm -rf /tmp/whitelist.lock
rm -rf /tmp/blacklist.lock
/etc/init.d/wifidog restart&
/etc/init.d/whitelist restart&
/etc/init.d/qos restart&
