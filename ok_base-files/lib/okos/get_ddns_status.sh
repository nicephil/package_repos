#!/bin/sh
provider=$(echo $1 | tr '.' '_')
msg=$(cat /var/run/ddns/${provider}.dat | awk '{if(NF==2){print $1"_"$2}}' 2>/dev/null)
mtime=$(cat /var/run/ddns/${provider}.update)
[ -z "$msg" ] && {
    echo "{}"
    exit  0
}
OIFS=$IFS;IFS='_';set -- $msg;__status=$1;__ip=$2;IFS=$OIFS

echo "{\"status\":\"$__status\",\"ip\":\"$__ip\",\"mtime\":\"$mtime\"}"
