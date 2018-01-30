#!/bin/sh

/etc/init.d/network restart
sync;echo 3 > /proc/sys/vm/drop_caches
sleep 15
/etc/init.d/wifidog restart&
/etc/init.d/qos restart&
/etc/init.d/arpwatch restart&
/lib/okos/apfw.dyn restart&
