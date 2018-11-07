#!/bin/sh

<<<<<<< HEAD
scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/master_for_BB-14.07/osdk_repos/package_repos/ok_base-files/lib/* /lib/.
scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/master_for_BB-14.07/osdk_repos/package_repos/ok_base-files/sbin/* /sbin/.
scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/master_for_BB-14.07/osdk_repos/package_repos/ok_base-files/etc/* /etc/.

=======
scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/lib/okos/* /lib/okos/.
scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/lib/upgrade/* /lib/upgrade/.


/etc/init.d/okos_mgr restart
>>>>>>> remotes/origin/okos_firmware_for_x86_gw
