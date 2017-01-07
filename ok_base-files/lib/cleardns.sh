#!/bin/sh

. /lib/functions.sh

list_cb() {
  local name="$1"
  local value="$2"
  
  sed -i "/${value}/d" /etc/resolv.conf
  
}

config_load dns

