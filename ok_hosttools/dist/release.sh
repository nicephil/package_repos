#!/bin/sh

all_types="EdgeRouter_ER-X"
url="api.oakridge.io"
img_url="http://image.oakridge.vip:8000/images/ap/ubnterx/okos/latest-okos.gz"
wget ${img_url}.md5sum -O tmp.md5sum
img_md5=$(cat tmp.md5sum)
echo "new release: $img_md5"



echo "====> query old release md5"
echo ./dist_release.py $url -A deploy -s --type $all_types
./dist_release.py $url -A deploy -s --type $all_types

echo "unbind release:"
read unbind_md5

echo "====> unbind old release"
echo ./dist_release.py $url -A deploy -U --type $all_types --md5 $unbind_md5
./dist_release.py $url -A deploy -U --type $all_types --md5 $unbind_md5

echo "====> delete old release"
echo ./dist_release.py $url -A release -d --md5 $unbind_md5
./dist_release.py $url -A release -d --md5 $unbind_md5

echo "====> add new release md5"
echo ./dist_release.py $url -A release -a --type $all_types --url $img_url --md5 $img_md5
./dist_release.py $url -A release -a --type $all_types --url $img_url --md5 $img_md5


echo "====> bind new release"
echo ./dist_release.py $url -A deploy -S --type $all_types --url $img_url --md5 $img_md5
./dist_release.py $url -A deploy -S --type $all_types --url $img_url --md5 $img_md5

echo "====> query new release"
echo ./dist_release.py $url -A deploy -s --type $all_types
./dist_release.py $url -A deploy -s --type $all_types

rm -rf tmp.md5sum
