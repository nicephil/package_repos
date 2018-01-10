#!/bin/sh

/etc/init.d/network restart
sync;echo 3 > /proc/sys/vm/drop_caches
sleep 15
rm -rf /tmp/qos.lock
rm -rf /tmp/whitelist.lock
rm -rf /tmp/blacklist.lock
rm -rf /tmp/.iptables.lock
/etc/init.d/wifidog restart&
/etc/init.d/qos restart&
iptables -F client_wan_uplink_traf&
iptables -F client_wan_downlink_traf&
/etc/init.d/arpwatch restart&
