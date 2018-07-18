#!/bin/sh
hostname=$1
msg=$(cat /var/cache/ddclient/ddclient.cache | awk -F',' '/host='"$hostname"'/{i=1;if(NF<7)next;print "{";while(i++<=13){split($i,aa,"=");print "\""aa[1]"\":\""aa[2]"\",";}print"\"dummy\":\"\"}"}' 2>/dev/null)
[ -z "$msg" ] && {
    echo "{}"
    exit  0
}

echo $msg
