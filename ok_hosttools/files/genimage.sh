#!/bin/bash
swversion=$1
origin_files__bin_files="openwrt-ar71xx-generic-vmlinux-initramfs.elf|vmlinux_ap152_16M.gz|ap152 openwrt-ar71xx-generic-vmlinux-initramfs.elf|vmlinux_ubnt_unifi.gz|ubntunifi"
server=image.oakridge.vip



for origin_file__bin_file in ${origin_files__bin_files}
do

OIFS=$IFS;IFS="|"; set -- ${origin_file__bin_file};origin_file=$1;bin_file=$2;rdir=$3;IFS=$OIFS
echo "${origin_file} --- ${bin_file}"
gzip -c "${origin_file}" > "${bin_file}"

[ -n "$swversion" ] && {
    mv ${bin_file} ${swversion}_${bin_file}
    # upload
    scp ${swversion}_${bin_file} image@${server}:/var/www/html/images/ap/${rdir}/okos/.
    ssh image@${server} "cd /var/www/html/images/ap/${rdir}/okos;
    unlink latest-okos.gz;ln -s ${swversion}_${bin_file} latest-okos.gz;"
}
done
