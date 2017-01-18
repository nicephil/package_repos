#!/bin/sh

if [[ -f /tmp/fresharplist.lock ]]
then
exit 0
fi

touch /tmp/fresharplist.lock

mgt=`ifconfig | awk -F'[: ]' '$1 ~ /br-lan/{a=1;print $1;} $11 ~ /inet/{if(a&&$13){print $13;exit}}'`
mgtif=`echo $mgt | awk '{print $1}'`
mgtip=`echo $mgt | awk '{print $2}'`
for i in `seq 1 50`
do
    arping -I $mgtif -c2 -f ${mgtip%\.*}.$i 2>&1 > /dev/null
done&
for i in `seq 50 100`
do
    arping -I $mgtif -c2 -f ${mgtip%\.*}.$i 2>&1 > /dev/null
done&
for i in `seq 100 150`
do
    arping -I $mgtif -c2 -f ${mgtip%\.*}.$i 2>&1 > /dev/null
done&
for i in `seq 150 200`
do
    arping -I $mgtif -c2 -f ${mgtip%\.*}.$i 2>&1 > /dev/null
done&
for i in `seq 200 254`
do
    arping -I $mgtif -c2 -f ${mgtip%\.*}.$i 2>&1 > /dev/null
done &
wait
rm -rf /tmp/fresharplist.lock
