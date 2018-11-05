#!/bin/sh

other_image_servers="
alpha1.oakridge.vip
alpha1.oakridge.io
alpha2.oakridge.vip
alpha2.oakridge.io
beta1.oakridge.vip
beta1.oakridge.io
beta2.oakridge.vip
beta2.oakridge.io
nms1.oakridge.vip
nms1.oakridge.io
nms2.oakridge.vip
nms2.oakridge.io
"
other_image_servers="
alpha1.oakridge.io
beta2.oakridge.io
nms1.oakridge.vip
nms1.oakridge.io
"

lbase_dir="/var/www/html/images"
rbase_dir="/var/www/html/images"

rsync_dirs="
./ap/hcmt7621-n256/okos
./ap/ap152/okos
./ap/ubntunifi/okos
./ap/ubnterx/okos
./x86_gw/okos
./ap/xiaomi3g_gw/okos
./ap/xiaomi3g/okos
./ap/xiaomi3/okos
"

for server in $other_image_servers
do
    nc -vz -w3 $server 22
    if [ "$?" != "0" ]
    then
        echo "$server port 22 is unreachable"
        continue
    fi
    for dir in $rsync_dirs
    do
        rsync -ravz --delete --progress $lbase_dir/$dir/ $server:$rbase_dir/$dir &
    done
done

wait
