#!/bin/sh

/etc/init.d/supervisor stop
/etc/init.d/wifidog stop
/etc/init.d/qos stop
iptables -F client_wan_uplink_traf&
iptables -F client_wan_downlink_traf&
/etc/init.d/arpwatch stop
sync;echo 3 > /proc/sys/vm/drop_caches
wifi down &
