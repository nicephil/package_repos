#!/bin/sh

help()
{
    cat <<_HELP_
Setup statistic entries in iptables.

Usage:  $0 {set|del} [OPTIONS] IPADDR/MAC[,IPADDR/MAC]

Example:
    $0 set 192.168.254.132/a86bad199c37,192.168.254.99/080027e4d6ff
_HELP_
}

case "$1" in
    set) cmd="$1";;
    del) cmd="$1";;
    *) echo "unknown cmd $1"; help; exit 1;;
esac
shift 1

while [ -n "$1" ]; do
    case $1 in
        --) shift;break;;
        -*) echo "unknown option $1"; help;exit 2;;
        *) break;;
    esac
done

entries="$1"
chains="statistic_tx statistic_rx statistic_tx_wan statistic_rx_wan"
ipt="iptables -w -t mangle"
rx="rx"
tx="tx"

for entry in ${entries//,/ }; do
    OIFS=$IFS;IFS='/';set -- $entry;ipaddr=$1;mac=$2;IFS=$OIFS
    for chain in $chains ; do
        if [ "${chain/$rx}" != "$chain" ]; then
            match="-d"
        else
            match="-s"
        fi
        rule="$chain $match $ipaddr -m comment --comment \"$mac\" -j RETURN"
        echo $rule
        case "$cmd" in
            set)
                $ipt -C $rule > /dev/null 2>&1
                [ "$?" -ne 0 ] && $ipt -A $rule
                ;;
            del)
                $ipt -C $rule > /dev/null 2>&1
                [ "$?" -eq 0 ] && $ipt -D $rule
                ;;
            *) help; exit 11;;
        esac
    done
done