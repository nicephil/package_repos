#!/bin/sh

ts=`date +%s`
NF_LOG="/tmp/nf.log"
PREV_NF_LOG=`ls /tmp/nf_prev_*.log 2>/dev/null`
OIFS=$IFS; IFS="[_.]"; set -- $PREV_NF_LOG; prev_ts=$3;IFS=$OIFS
#echo "-->$prev_ts"

function client_trap()
{
    lock -u /tmp/client.lock
}

lock /tmp/client.lock
trap 'client_trap; exit' INT TERM ABRT QUIT ALRM

cat /proc/net/arp > /tmp/nf1 2>/dev/null
cat /proc/net/nf_conntrack > /tmp/nf2 2>/dev/null

awk '

ARGIND==1{
    if (!match($1, "IP")) {
        arp[$1,1]=$4;
        arp[$1,2]=$6;
    }
}

ARGIND==2{
    if (match($1,"ipv4") && !match($0, "0.0.0.0") && !match($0, "127.0.0.1")) {
        tmp1=1;
        tmp2=1;
        for (i=1; i < NF; i++) {
            if (tmp1 && match($i,"src")) {
                src=$i;
                tmp1=0;
                continue;
            } else if (match($i, "bytes")) {
                if (tmp2) {
                    ups=$i;
                    tmp2=0;
                    continue;
                } else {
                    downs=$i;
                    break;
                }
            }
        }
    }
    if (!length(src)) {
        next;
    }
    split(src,a,"=");
    split(ups,b,"=");
    split (downs,c,"=");
    uplink[a[2],1]+=b[2];
    uplink[a[2],2]+=c[2];
}

END {
    for (key in uplink) { 
        split(key,k,SUBSEP);
        if (k[2] == 1) {
            if (length(arp[k[1],2])) {
                cmd=". /lib/functions/network.sh;network_get_lname __lname \""arp[k[1],2]"\";echo $__lname";
                cmd|getline lname;
                close(cmd)
                print k[1],uplink[k[1],1], uplink[k[1],2], arp[k[1],1], arp[k[1],2], lname;
            }
        }
    }
}

' /tmp/nf1 /tmp/nf2 > $NF_LOG 2>/dev/null


rm -f "$PREV_NF_LOG"
mv -f "$NF_LOG" "/tmp/nf_prev_${ts}.log"
cat "/tmp/nf_prev_${ts}.log"

lock -u /tmp/client.lock
