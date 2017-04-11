#!/bin/bash
origin_file="openwrt-ar71xx-generic-ap152-16M-squashfs-sysupgrade.bin"
bin_file="bin_ap152_16M.app"

tar czf ${origin_file}.tar.gz ${origin_file}

# 64bytes header
header="\x27\x05\x19\x56\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\
\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\
\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\
\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
echo -e "${header}" > ${bin_file}
cat ${origin_file}.tar.gz >> ${bin_file}

[ -n "$1" ] && {
    mv ${bin_file} "$1"_${bin_file}
    mv ${origin_file}.tar.gz "$1"_${origin_file}.tar.gz
}

