#!/bin/sh

ip=$1


function test_upgrade_sysloader()
{
    scp -P22001 -r /home/llwang/repos/x86/osdk_repos_sysloader/bin/targets/x86/64/lede-x86-64-combined-squashfs.img root@$1:/tmp/
    ssh -p22001 root@$1 "sysupgrade -n /tmp/lede-x86-64-combined-squashfs.img;"
}
function test_okos_scripts()
{
    scp -P22001 -r /home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/lib/okos/* root@$1:/lib/okos/.
}

function test_busybox()
{
    scp -P22001 -r /home/llwang/repos/x86/osdk_reposr/packages/x86/64/busybox_1.19.4-6_ar71xx.ipk root@$1:/tmp/
    ssh -p 22001 root@$1 "/etc/init.d/handle_cloud stop;rm -rf /root/*;opkg remove --force-removal-of-essential-packages --force-depends busybox;opkg install /tmp/*.ipk;/etc/init.d/boot restart;"
}


#test_okos_scripts $ip

test_upgrade_sysloader $ip
#test_load_okos $ip

#test_busybox $ip

