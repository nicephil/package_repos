#!/bin/sh

scp -r llwang@192.168.254.191:/home/llwang/repos/x86/osdk_repos/package_repos/ok_base-files/lib/okos/* /lib/okos/.


/etc/init.d/okos_mgr restart
