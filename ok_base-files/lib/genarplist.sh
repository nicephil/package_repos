#!/bin/sh

mgtif=br-lan1
mgtip=`ifconfig $mgtif | awk -F'[ :\t]' '/inet addr/{print $14}'`
for i in `seq 254`
do
    arping -I $mgtif -c1 -f ${mgtip%\.*}.$i&
done
