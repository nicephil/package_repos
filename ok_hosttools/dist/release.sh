#!/bin/sh

all_types="A820 A822 A826 A920 A923 W282 WL8200-I2 AC-PRO AC-LITE AC-LR ubntlr ubntlite ubntpro SEAP-380 A750 A751"
url="api.oakridge.vip"

echo "====> query old release md5"
echo ./dist_release.py $url -A deploy -s --type $all_types
./dist_release.py $url -A deploy -s

echo "unbind release:"
read unbind_md5

echo "====> unbind old release"
echo ./dist_release.py $url -A deploy -U --md5 $unbind_md5 --type $all_types
./dist_release.py $url -A deploy -U --md5 $unbind_md5 --type $all_types



echo "====> query old release md5"
echo ./dist_release.py $url -A deploy -s --type $all_types
./dist_release.py $url -A deploy -s

echo "new url"
read img_url

echo "new md5"
read img_md5

echo "====> bind new release"
echo ./dist_release.py $url -A deploy -S --md5 $img_md5 --type $all_types --url $img_url 
./dist_release.py $url -A deploy -S --url $img_url --md5 $img_md5 --type $all_types

echo "====> query new release"
echo ./dist_release.py $url -A deploy -s --type $all_types
./dist_release.py $url -A deploy -s
