#!/bin/sh

all_macs="f0:9f:c2:6d:24:7e"
all_types="EdgeRouter_ER-X"
url="api.oakridge.io"
img_url="http://image.oakridge.vip:8000/images/ap/ubnterx/okos/latest-okos.gz"
wget ${img_url}.md5sum -O tmp.md5sum
img_md5=$(cat tmp.md5sum)
echo "new release: $img_md5"



echo "====> query old release md5"
echo ./dist_release.py $url -A employe -s --macs $all_macs
./dist_release.py $url -A employe -s --macs $all_macs

echo "unbind release:"
read unbind_md5

echo "====> unbind old release"
echo ./dist_release.py $url -A employe -u --macs $all_macs --md5 $unbind_md5
./dist_release.py $url -A employe -u --macs $all_macs --md5 $unbind_md5

echo "====> delete old release"
echo ./dist_release.py $url -A release -d --md5 $unbind_md5
./dist_release.py $url -A release -d --md5 $unbind_md5

echo "====> add new release md5"
echo ./dist_release.py $url -A release -a --type $all_types --url $img_url --md5 $img_md5
./dist_release.py $url -A release -a --type $all_types --url $img_url --md5 $img_md5


echo "====> bind new release"
echo ./dist_release.py $url -A employe -b --macs $all_macs --url $img_url --md5 $img_md5
./dist_release.py $url -A employe -b --macs $all_macs --url $img_url --md5 $img_md5

echo "====> query new release"
echo ./dist_release.py $url -A employe -s --macs $all_macs
./dist_release.py $url -A employe -s --macs $all_macs

rm -rf tmp.md5sum
