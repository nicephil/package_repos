#!/bin/bash
swversion=$1
origin_files__bin_files="openwrt-ar71xx-generic-ap152-16M-squashfs-sysupgrade.bin|bin_ap152_16M.app|ap152 openwrt-ar71xx-generic-ubnt-unifi-squashfs-sysupgrade.bin|bin_ubnt_unifi.app|ubntunifi"
server=image.oakridge.vip



for origin_file__bin_file in ${origin_files__bin_files}
do

OIFS=$IFS;IFS="|"; set -- ${origin_file__bin_file};origin_file=$1;bin_file=$2;rdir=$3;IFS=$OIFS
echo "${origin_file} --- ${bin_file}"
tar czf ${origin_file}.tar.gz ${origin_file}

# 64bytes header
header="\x27\x05\x19\x56\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\
\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\
\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\
\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
echo -e "${header}" > ${bin_file}
cat ${origin_file}.tar.gz >> ${bin_file}

[ -n "$swversion" ] && {
    mv ${bin_file} ${swversion}_${bin_file}
    mv ${origin_file}.tar.gz ${swversion}_${origin_file}.tar.gz
    # upload
    scp ${swversion}_${bin_file} ${swversion}_${origin_file}.tar.gz image@${server}:/var/www/html/images/ap/${rdir}/.
    ssh image@${server} "cd /var/www/html/images/ap/${rdir};
    unlink latest-bin.app;ln -s ${swversion}_${bin_file} latest-bin.app;
    unlink latest-sysupgrade.bin.tar.gz; ln -s ${swversion}_${origin_file}.tar.gz latest-sysupgrade.bin.tar.gz"
}
done
