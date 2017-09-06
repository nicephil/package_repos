#!/bin/sh

ROUTE_FILE='/lib/netifd/dhcp.script'
FW_FILE='/etc/init.d/apfw'

sed -i -e '28s/lan1/wan/' -e '29s/lan1/wan/' $ROUTE_FILE

sed -i '19 a iptables -A Firewall -i br-lan+ -p udp -m udp --dport 67 -j ACCEPT' $FW_FILE
sed -i '19 a iptables -A Firewall -i br-lan+ -p udp -m udp --dport 53 -j ACCEPT' $FW_FILE
sed -i '26 a iptables -t nat -A POSTROUTING -o eth0.4090 -j MASQUERADE' $FW_FILE

