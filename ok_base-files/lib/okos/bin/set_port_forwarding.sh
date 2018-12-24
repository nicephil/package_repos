#!/bin/sh

help()
{
    cat <<_HELP_
Setup port forwarding entry.
 
Usage:  $0 del ID [-S]
        $0 set ID --src-zone ZONE --dst-zone ZONE 
            [--src-ip IP] [--src-dip IP] [--dst-ip IP]
            [--src-port PORT] [--src-dport PORT] [--dst-port PORT]
            [--src-mac MAC] [--proto PROTO] [--action ACTION] [-S]
            
        ID # use ID to identify each port forwarding entry. 
           # Caller MUST ensure it's unique.
           # [a-zA-z][a-zA-Z0-9_]{,9}
        --src-zone {TRUSTED|UNTRUSTED|DMZ|GUEST} # assign source security zone of traffic
        --dst-zone {TRUSTED|UNTRUSTED|DMZ|GUEST} # assign destinate security zone of traffic
        --src-ip IP # source ip address of input traffic
        --src-dip IP # destinate ip addresss of input traffice
        --dst-ip IP # ip address of target in the local network
        --src-port PORT # sourc port of input traffic
        --src-dport PORT # destinate port of input traffic
        --dst-port PORT # destinate port on the target
        --src-mac MAC # source mac address of input traffic
        --proto {*tcpudp|tcp|udp} # protocol
        --action {*DNAT|SNAT} # target of this entry, DNAT by default.
        -S # don't restart service
Example:
    # mapping all the traffic targeted to wan port's tcp port 22 to local host 172.16.254.145 with same dest port.
    $0 set ssh_to_svr --src-zone UNTRUSTED --dst-zone TRUSTED --src-dport 22 --dst-ip 172.16.254.145 -p tcp
    # mapping an external ip 10.0.1.4 to internal server 172.16.254.145
    $0 set webserver_3 --src-zone UNTRUSTED --dst-zone DMZ --src-dip 10.0.1.4 --dst-ip 172.16.254.145
_HELP_
}

case "$1" in
    set) cmd="$1";;
    del) cmd="$1";;
    *) echo "unknown command $1"; help;exit 1;;
esac
shift 1

echo 'Caller MUST ensure that ID is unique.'
id="$1"
shift 1

proto='tcpudp'
target='DNAT'
while [ -n "$1" ]; do
    case $1 in
        --src-zone) src_zone="$2";shift 2;;
        --dst-zone) dst_zone="$2";shift 2;;
        --src-ip) src_ip="$2";shift 2;;
        --src-dip) src_dip="$2";shift 2;;
        --dst-ip) dst_ip="$2";shift 2;;
        --src-port) src_port="$2";shift 2;;
        --src-dport) src_dport="$2";shift 2;;
        --dst-port) dst_port="$2";shift 2;;
        --src-mac) src_mac="$2";shift 2;;
        --proto) proto="$2";shift 2;;
        --action) target="$2";shift 2;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) echo "unknown option $1"; help;exit 2;;
        *) break;;
    esac
don

_del_pfwd()
{
    uci get firewall.${id} >/dev/null 2>&1
    [ "$?" == 0 ] && uci delete firewall.${id}
}

set_pfwd()
{
    _del_pfwd

    case "$src_zone" in
        TRUSTED) src_zone_id='0';;
        UNTRUSTED) src_zone_id='1';;
        DMZ) src_zone_id='2';;
        GUEST) src_zone_id='3';;
        *) echo 'unknown src-zone'; help; exit 3;;
    esac
    case "$dst_zone" in
        TRUSTED) dst_zone_id='0';;
        UNTRUSTED) dst_zone_id='1';;
        DMZ) dst_zone_id='2';;
        GUEST) dst_zone_id='3';;
        *) echo 'unknown dst-zone'; help; exit 4;;
    esac
    case "$target" in
        DNAT) target="$target";;
        SNAT) target="$target";;
        *) echo 'unknown target'; help; exit 5;;
    esac
    [ -z "$dst_ip" ] && dst_ip="$src_dip"
    [ -z "$dst_port" ] && dst_port="$src_dport"
    echo "Port Forwarding [${src_dip}:${src_dport}] to [${dst_ip}:${dst_port}] for protocol $proto"

    uci set firewall.${id}='redirect'
    uci set firewall.${id}.name="${id}"
    [ -n "$src_zone" ] && uci set firewall.${id}.src="${src_zone}"
    [ -n "$dst_zone" ] && uci set firewall.${id}.dest="${dst_zone}"
    [ -n "$src_ip" ] && uci set firewall.${id}.src_ip="${src_ip}"
    [ -n "$src_dip" ] && uci set firewall.${id}.src_dip="${src_dip}"
    [ -n "$dst_ip" ] && uci set firewall.${id}.dest_ip="${dst_ip}"
    [ -n "$src_port" ] && uci set firewall.${id}.src_port="${src_port}"
    [ -n "$src_dport" ] && uci set firewall.${id}.src_dport="${src_dport}"
    [ -n "$dst_port" ] && uci set firewall.${id}.dest_port="${dst_port}"
    [ -n "$src_mac" ] && uci set firewall.${id}.src_mac="${src_mac}"
    [ -n "$proto" ] && uci set firewall.${id}.proto="${proto}"
    [ -n "$target" ] && uci set firewall.${id}.target="${target}"
}

del_pfwd()
{
    echo "Remove port forwarding <${id}>"
    _del_pfwd
}

case "$cmd" in
    set) set_pfwd;;
    del) del_pfwd;;
    *) help;exit 6;;
esac

uci commit firewall


if [ -z "$no_restart" ]; then
    /etc/init.d/firewall reload
fi

exit 0