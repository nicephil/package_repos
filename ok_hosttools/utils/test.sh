#!/bin/sh

ip=$1

./deploysshkey.sh $ip

function test_capwapc_and_libs()
{
    scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/bin/ar71xx/packages/libservices_1.0-0_ar71xx.ipk root@$1:/tmp/
    scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/bin/ar71xx/packages/libnmsc_1.0-0_ar71xx.ipk root@$1:/tmp/
    scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/bin/ar71xx/packages/capwapc_1_ar71xx.ipk root@$1:/tmp/
    ssh root@$1 "/etc/init.d/handle_cloud stop;opkg remove --force-depends capwapc libnmsc libservices;opkg install /tmp/*.ipk;/etc/init.d/capwapc restart;"
}

function test_capwapc()
{
    scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/bin/ar71xx/packages/capwapc_1_ar71xx.ipk root@$1:/tmp/
    ssh root@$1 "/etc/init.d/handle_cloud stop;opkg remove --force-depends capwapc;opkg install /tmp/*.ipk;/etc/init.d/capwapc restart;"
}


function test_okos_scripts()
{
    scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/package_repos/ok_base-files/lib/okos/* root@$1:/lib/okos/.
}

function test_busybox()
{
    scp -r /home/llwang/repos/master_for_AA-12.09/osdk_repos/bin/ar71xx/packages/busybox_1.19.4-6_ar71xx.ipk root@$1:/tmp/
    ssh root@$1 "/etc/init.d/handle_cloud stop;rm -rf /root/*;opkg remove --force-removal-of-essential-packages --force-depends busybox;opkg install /tmp/*.ipk;/etc/init.d/boot restart;"
}


#test_capwapc $ip

test_okos_scripts $ip

#test_busybox $ip

