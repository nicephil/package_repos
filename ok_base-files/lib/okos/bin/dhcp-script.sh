#!/bin/sh

#################################################################################################
# daemon.info dnsmasq-dhcp[17002]: DHCPREQUEST(eth3.100) 192.168.254.111 64:b0:a6:e3:d0:d6 
# daemon.info dnsmasq-dhcp[17002]: DHCPACK(eth3.100) 192.168.254.111 64:b0:a6:e3:d0:d6 BlackLeaf
# daemon.debug dnsmasq-script[17002]: old 64:b0:a6:e3:d0:d6 192.168.254.111 BlackLeaf # echo $@
# daemon.debug dnsmasq-script[17002]: SHLVL=2                                         # env
# daemon.debug dnsmasq-script[17002]: HOME=/
# daemon.debug dnsmasq-script[17002]: DNSMASQ_LEASE_LENGTH=86400
# daemon.debug dnsmasq-script[17002]: DNSMASQ_TIME_REMAINING=86400
# daemon.debug dnsmasq-script[17002]: DNSMASQ_DOMAIN=hz.oakridge.io
# daemon.debug dnsmasq-script[17002]: DNSMASQ_REQUESTED_OPTIONS=1,121,3,6,15,119,252
# daemon.debug dnsmasq-script[17002]: TERM=linux
# daemon.debug dnsmasq-script[17002]: BOOT_IMAGE=/boot/vmlinuz
# daemon.debug dnsmasq-script[17002]: PATH=/usr/sbin:/usr/bin:/sbin:/bin
# daemon.debug dnsmasq-script[17002]: DNSMASQ_CLIENT_ID=01:64:b0:a6:e3:d0:d6
# daemon.debug dnsmasq-script[17002]: DNSMASQ_SUPPLIED_HOSTNAME=BlackLeaf
# daemon.debug dnsmasq-script[17002]: DNSMASQ_TAGS=eth3.100
# daemon.debug dnsmasq-script[17002]: PWD=/
# daemon.debug dnsmasq-script[17002]: DNSMASQ_INTERFACE=eth3.100

status="$1"
mac="$2"
ipaddr="$3"
hostname="$4"

option55="$DNSMASQ_REQUESTED_OPTIONS"
[ -z "$hostname" ] && hostname="$DNSMASQ_SUPPLIED_HOSTNAME"
iface="$DNSMASQ_INTERFACE"

mac=${mac//:/}
echo "{'sta_mac':'${mac}','logmsg':'$hostname accquired $ipaddr on $iface'}" | logger -p 6 -t "200-STA"

clientdatabase='clientdatabase.oakridge.io:8103'

# update hostname
if [ -n $hostname ]; then
    json_data="'{\"clients\":{\"${mac}\":{\"hostname\":\"${hostname}\"}}}'"
    # echo $json_data
    cmd="curl -X POST -H 'Content-Type: application/json' 'http://${clientdatabase}/clientdatabase/v0/client/report?key=1' --data $json_data"
    echo $cmd
    eval $cmd >/dev/null 2>&1
fi

# upload dhcp fingerprint to clientdatabase
if [ -n $DNSMASQ_REQUESTED_OPTIONS ]; then
    json_data="'{\"clients\":{\"${mac}\":{\"dhcp_fingerprint\":\"${option55}\"}}}'"
    # echo $json_data
    cmd="curl -X POST -H 'Content-Type: application/json' 'http://${clientdatabase}/clientdatabase/v0/client/analyzor?key=1' --data $json_data"
    echo $cmd
    eval $cmd >/dev/null 2>&1
fi

