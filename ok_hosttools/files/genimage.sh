#!/bin/bash
swversion=$1
origin_files__bin_files="lede-x86-generic-combined-squashfs.img.gz|bin.app|x86_gw"
server=image.oakridge.vip



for origin_file__bin_file in ${origin_files__bin_files}
do

OIFS=$IFS;IFS="|"; set -- ${origin_file__bin_file};origin_file=$1;bin_file=$2;rdir=$3;IFS=$OIFS
echo "${origin_file} --- ${bin_file}"
echo "$swversion" > swversion.txt
tar czf ${origin_file}.tar.gz ${origin_file} swversion.txt
echo "$swversion" > latest-swversion.txt

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
    md5sum ${swversion}_${bin_file} | awk '{print $1}' > ${swversion}_${bin_file}.md5sum
    md5sum ${swversion}_${origin_file}.tar.gz | awk '{print $1}' > ${swversion}_${origin_file}.tar.gz.md5sum
    # upload
    scp latest-swversion.txt ${swversion}_${bin_file} ${swversion}_${origin_file}.tar.gz ${swversion}_${bin_file}.md5sum ${swversion}_${origin_file}.tar.gz.md5sum image@${server}:/var/www/html/images/${rdir}/sysloader/.
    ssh image@${server} "cd /var/www/html/images/${rdir}/sysloader;
    ln -sf ${swversion}_${bin_file} latest-bin.app;
    ln -sf ${swversion}_${origin_file}.tar.gz latest-sysupgrade.bin.tar.gz;
    ln -sf ${swversion}_${bin_file}.md5sum latest-bin.app.md5sum;
    ln -sf ${swversion}_${origin_file}.tar.gz.md5sum latest-sysupgrade.bin.tar.gz.md5sum;"
}
done
