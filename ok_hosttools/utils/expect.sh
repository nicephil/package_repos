#!/usr/bin/expect
# set timeout 20
if { $argc !=1 } {
    send_user "Usage:expect <ssh port>\n"
    exit
}
set port [lindex $argv 0]
spawn ssh -y -p $port root@localhost
expect "*password:" { send "oakridge\n" }
expect "*#" { send "ls -la /tmp/;ps w;top -b -n1\n" }
interact
