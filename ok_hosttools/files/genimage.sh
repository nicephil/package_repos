#!/bin/bash
swversion=$1
origin_files__bin_files="vmlinux-initramfs.elf|bin_ubnt_erx.gz|ubnterx"
server=image.oakridge.vip

function add_new_release() 
{
    dist_release="../../package_repos/ok_hosttools/dist/dist_release.py"
    img_name=$1
    img_md5=$2

    img_url="http://image.oakridge.vip:8000/images/ap/ubnterx/okos/${img_name}"

    all_types="EdgeRouter_ER-X ubnterx"
    url="api.oakridge.io"
    echo "new release:$img_md5 ${img_url}"

    echo "====> add new release md5"
    echo $dist_release $url -A release -a --type $all_types --url $img_url --md5 $img_md5
    $dist_release $url -A release -a --type $all_types --url $img_url --md5 $img_md5

    echo "====> query new release"
    echo $dist_release $url -A deploy -s --type $all_types
    $dist_release $url -A deploy -s
}

for origin_file__bin_file in ${origin_files__bin_files}
do

    OIFS=$IFS;IFS="|"; set -- ${origin_file__bin_file};origin_file=$1;bin_file=$2;rdir=$3;IFS=$OIFS
    echo "${origin_file} --- ${bin_file}"
    gzip -c "${origin_file}" > "${bin_file}"

    [ -n "$swversion" ] && {
        mv ${bin_file} ${swversion}_${bin_file}
        md5sum ${swversion}_${bin_file} | awk '{print $1}' > ${swversion}_${bin_file}.md5sum
        # upload
        scp ${swversion}_${bin_file} ${swversion}_${bin_file}.md5sum image@${server}:/var/www/html/images/ap/${rdir}/okos/.
        ssh image@${server} "cd /var/www/html/images/ap/${rdir}/okos;
        ln -sf ${swversion}_${bin_file} latest-okos.gz;
        ln -sf ${swversion}_${bin_file}.md5sum latest-okos.gz.md5sum"
    }

    if [ $rdir = "ubnterx" ]
    then
        add_new_release ${swversion}_${bin_file} $(cat ${swversion}_${bin_file}.md5sum)
    fi
done
