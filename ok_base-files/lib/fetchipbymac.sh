#!/bin/sh

mac=$1

awk '{if ($4 == "'$mac'") print "\toption ipaddr "$1;}' /proc/net/arp

