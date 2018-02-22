#!/bin/sh

all_types="A820 A822 A920 A923 W282 WL8200-I2 AC-PRO AC-LITE AC-LR ubntlr ubntlite ubntpro"
url="api.oakridge.io"
img_url="http://image.oakridge.vip:8000/images/ap/ap152/okos/latest-okos.gz"
wget ${img_url}.md5sum -O /tmp/tmp.md5sum
img_md5=$(cat /tmp/tmp.md5sum)
echo "new release:$img_md5"



echo "====> query old release md5"
echo ./dist_release.py $url -A deploy -s --type $all_types
./dist_release.py $url -A deploy -s

echo "unbind release:"
read unbind_md5

echo "====> unbind old release"
echo ./dist_release.py $url -A deploy -U --md5 $unbind_md5 --type $all_types
./dist_release.py $url -A deploy -U --md5 $unbind_md5 --type $all_types

echo "====> delete old release"
echo ./dist_release.py $url -A release -d --md5 $unbind_md5
./dist_release.py $url -A release -d --md5 $unbind_md5

echo "====> add new release md5"
echo ./dist_release.py $url -A release -a --type $all_types --url $img_url --md5 $img_md5
./dist_release.py $url -A release -a --type $all_types --url $img_url --md5 $img_md5


echo "====> bind new release"
echo ./dist_release.py $url -A deploy -S --md5 $img_md5 --type $all_types --url $img_url 
./dist_release.py $url -A deploy -S --url $img_url --md5 $img_md5 --type $all_types

echo "====> query new release"
echo ./dist_release.py $url -A deploy -s --type $all_types
./dist_release.py $url -A deploy -s
rm -rf /tmp/tmp.md5sum
