#!/bin/bash

imagebuilder=lede-imagebuilder-ramips-mt7621.Linux-x86_64
sdk=lede-sdk-ramips-mt7621_gcc-5.4.0_musl-1.1.16.Linux-x86_64


[ ! -f "${imagebuilder}.tar.xz" ] && {
wget 'http://a1.oakridge.io:8000/${imagebuilder}.tar.xz'
}

[ ! -f "${sdk}.tar.xz" ] && {
wget 'http://a1.oakridge.io:8000/${sdk}.tar.xz'
}

[ ! -e "../../${sdk}" ] && {
tar xvJf  lede-sdk-ramips-mt7621_gcc-5.4.0_musl-1.1.16.Linux-x86_64.tar.xz -C ../..
}

[ ! -e "../../${sdk}" ] && {
tar xvJf ${sdk}.tar.xz -C ../..
}

cd ../../${sdk}

cp -rvf ../package_repos .


./scripts/feeds update -a 
./scripts/feeds install -p ok_package -a

make defconfig

make V=s 2>&1 | tee build.log


