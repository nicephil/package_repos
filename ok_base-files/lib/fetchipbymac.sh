#!/bin/sh

mac=$1

ip=`awk '{if ($4 == "'$mac'") print "\toption ipaddr "$1;}' /proc/net/arp`

if [[ -n "$ip" ]]
then
  echo -e "$ip"
  exit 0
fi

/lib/fresharplist.sh &
