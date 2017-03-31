#!/bin/sh

/etc/init.d/network restart
sleep 15
/etc/init.d/wifidog restart&
