#!/bin/sh

all_macs="f0:9f:c2:a6:19:7f f0:9f:c2:30:d4:80 fc:ad:0f:09:29:00 f0:9f:c2:f0:85:3e fc:ad:0f:07:ea:e0 78:8a:20:53:5b:73 fc:ad:0f:07:ed:50 fc:ad:0f:07:ed:a0"
all_types="A820 A822 A920 W282 WL8200-I2 AC-PRO AC-LITE AC-LR ubntlr ubntlite ubntpro"
url="api.oakridge.io"
img_url="http://image.oakridge.vip:8000/images/ap/ap152/okos/latest-okos.gz"
echo "new release:"
read img_md5



echo "====> query old release md5"
echo ./dist_release.py $url -A employe -s --macs $all_macs
./dist_release.py $url -A employe -s --macs $all_macs

echo "unbind release:"
read unbind_md5

echo "====> unbind old release"
echo ./dist_release.py $url -A employe -u --macs $all_macs --md5 $unbind_md5
./dist_release.py $url -A employe -u --macs $all_macs --md5 $unbind_md5

echo "====> add new release md5"
echo ./dist_release.py $url -A release -a --type $all_types --url $img_url --md5 $img_md5
./dist_release.py $url -A release -a --type $all_types --url $img_url --md5 $img_md5


echo "====> bind new release"
echo ./dist_release.py $url -A employe -b --macs $all_macs --url $img_url --md5 $img_md5
./dist_release.py $url -A employe -b --macs $all_macs --url $img_url --md5 $img_md5

echo "====> query new release"
echo ./dist_release.py $url -A employe -s --macs $all_macs
./dist_release.py $url -A employe -s --macs $all_macs
