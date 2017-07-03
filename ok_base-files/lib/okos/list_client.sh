#!/bin/sh


for ath in `iwconfig 2>/dev/null | awk '/ath/{print $1}'`
do
    echo "=====$ath===="
    wlanconfig $ath list sta
done
