#!/bin/bash
swversion=$1
origin_files__bin_files="openwrt-ar71xx-generic-vmlinux-initramfs.elf|vmlinux_ap152_16M.gz|ap152 openwrt-ar71xx-generic-vmlinux-initramfs.elf|vmlinux_ubnt_unifi.gz|ubntunifi"
server="image.oakridge.vip"
server=$(host -W 5 $server 2>/dev/null | awk '{if(!match($4,"found:"))print $4}')
[ -z "$server" ] && server="106.14.245.228"

function add_new_release() 
{
    dist_release="../../package_repos/ok_hosttools/dist/dist_release.py"
    img_name=$1
    img_md5=$2

    img_url="http://image.oakridge.vip:8000/images/ap/ap152/okos/${img_name}"

    all_types="A820 A822 A920 A923 W282 WL8200-I2 AC-PRO AC-LITE AC-LR ubntlr ubntlite ubntpro SEAP-380 A750"
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
        md5sum -b ${swversion}_${bin_file} | awk '{print $1}' > ${swversion}_${bin_file}.md5sum
        # upload
        scp ${swversion}_${bin_file} ${swversion}_${bin_file}.md5sum image@${server}:/var/www/html/images/ap/${rdir}/okos/.
        ssh image@${server} "cd /var/www/html/images/ap/${rdir}/okos;
        ln -sf ${swversion}_${bin_file} latest-okos.gz;
        ln -sf ${swversion}_${bin_file}.md5sum latest-okos.gz.md5sum"
        # add new release
        if [ $rdir = "ap152" ]
        then
            add_new_release ${swversion}_${bin_file} $(cat ${swversion}_${bin_file}.md5sum)
        fi
    }
done

# sync to other servers
ssh image "./rsync_image.sh"

