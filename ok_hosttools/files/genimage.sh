#!/bin/bash
swversion=$1
origin_files__bin_files="lede-x86-generic-ramfs.bzImage|bin_x86_generic_gw.bzImage|x86_gw"
server="image.oakridge.vip"
server=$(host -W 5 $server 2>/dev/null | awk '{if(!match($4,"found:"))print $4;exit}')
echo "1=>$server"
server="106.14.245.228"
echo "2=>$server"


function add_new_release() 
{
    dist_release="../../package_repos/ok_hosttools/dist/dist_release.py"
    img_name=$1
    img_md5=$2

    img_url="http://image.oakridge.vip:8000/images/x86_gw/okos/${img_name}"

    all_types="OKGW"
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
    cp "${origin_file}" "${bin_file}"

    [ -n "$swversion" ] && {
        mv ${bin_file} ${swversion}_${bin_file}
        md5sum ${swversion}_${bin_file} | awk '{print $1}' > ${swversion}_${bin_file}.md5sum
        # upload
        scp ${swversion}_${bin_file} ${swversion}_${bin_file}.md5sum image@${server}:/var/www/html/images/${rdir}/okos/.
        ssh image@${server} "cd /var/www/html/images/${rdir}/okos;
        ln -sf ${swversion}_${bin_file} latest-okos.bzImage;
        ln -sf ${swversion}_${bin_file}.md5sum latest-okos.bzImage.md5sum"
    }

    if [ $rdir = "x86_gw" ]
    then
        add_new_release ${swversion}_${bin_file} $(cat ${swversion}_${bin_file}.md5sum)
    fi
done

# sync to other servers
ssh image "./rsync_image.sh"
