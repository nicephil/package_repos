#!/bin/sh

scp -i /etc/id_rsa -r llwang@192.168.254.191:/home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/lib/okos/* /lib/okos/.


/etc/init.d/okos_mgr restart
