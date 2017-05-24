#!/bin/sh

/etc/init.d/network restart
sync;echo 3 > /proc/sys/vm/drop_caches
sleep 15
/etc/init.d/wifidog restart&
/etc/init.d/arpwatch restart&
/etc/init.d/whitelist restart&
/etc/init.d/ratelimit restart&
