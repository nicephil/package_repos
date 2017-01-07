#!/bin/sh

. /lib/functions.sh

list_cb() {        
  local name="$1"
  local value="$2"
  grep -q ${value} /etc/resolv.conf
  if [[ $? -ne 0 ]]                
  then             
    echo "nameserver ${value}" >> /etc/resolv.conf
  fi                                              

}                     

config_load dns

