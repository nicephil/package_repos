#!/bin/sh

# 0 23 * * *  /home/image/del_old_image.sh
lbase_dir="/var/www/html/images"
rsync_dirs="
./ap/ap152/okos
./ap/ubntunifi/okos
./ap/ubnterx/okos
./x86_gw/okos
./ap/xiaomi3g_gw/okos
./ap/xiaomi3g/okos
./ap/xiaomi3/okos
"

for dir in ${rsync_dirs}
do
	find ${lbase_dir}/${dir} -mtime +90 -type f -delete
done
