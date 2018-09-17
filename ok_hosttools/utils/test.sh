#!/bin/sh

ip=$1

./deploysshkey.sh $ip


function test_upgrade_sysloader()
{
    scp -P22001 -r /home/llwang/repos/x86/osdk_repos_sysloader/bin/targets/x86/generic/lede-x86-generic-combined-squashfs.img root@$1:/tmp/
    ssh -p22001 root@$1 "sysupgrade -n /tmp/lede-x86-generic-combined-squashfs.img;"
}
function test_rpcd_scripts()
{
    scp -P22001 -r /home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/usr/libexec/rpcd/* root@$1:/usr/libexec/rpcd/.
}
function test_okos_scripts()
{
    test_rpcd_scripts $1
    test_okos_config $1
    scp -P22001 -r /home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/lib/okos/* root@$1:/lib/okos/.
}
function test_okos_config()
{
    scp -P22001 -r /home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/etc/config/ddns root@$1:/etc/config/ddns
    scp -P22001 -r /home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/bin/config_generate root@$1:/bin/config_generate
}


function test_busybox()
{
    scp -P22001 -r /home/llwang/repos/x86/osdk_reposr/packages/x86/generic/busybox_1.19.4-6_ar71xx.ipk root@$1:/tmp/
    ssh -p 22001 root@$1 "/etc/init.d/handle_cloud stop;rm -rf /root/*;opkg remove --force-removal-of-essential-packages --force-depends busybox;opkg install /tmp/*.ipk;/etc/init.d/boot restart;"
}


test_okos_scripts $ip

#test_upgrade_sysloader $ip
#test_load_okos $ip

#test_busybox $ip

