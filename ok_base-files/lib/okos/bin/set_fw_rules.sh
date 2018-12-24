#!/bin/sh

help()
{
    cat <<_HELP_
Setup firewall rules.
 
Usage:  $0 del ID [-S]
        $0 set ID [--proto PROTO] [--icmp-type ICMP] [--action ACTION] [-S]
            [--src-zone ZONE] [--src-ip IP] [--src-port PORT] [--src-mac MAC]
            [--dst-zone ZONE] [--dst-ip IP] [--dst-port PORT]
            
        ID # use ID to identify each port forwarding entry. 
           # Caller MUST ensure it's unique.
           # [a-zA-z][a-zA-Z0-9_]{,9}
        --src-zone {TRUSTED|UNTRUSTED|DMZ|GUEST} # assign source security zone of traffic
        --dst-zone {TRUSTED|UNTRUSTED|DMZ|GUEST} # assign destinate security zone of traffic
        --src-ip IP # source ip address of input traffic
        --dst-ip IP # ip address of target in the local network
        --src-port PORT # sourc port of input traffic
        --dst-port PORT # destinate port on the target
        --src-mac MAC # source mac address of input traffic
        --proto {tcp|udp|tcpudp|udplite|icmp|esp|ah|sctp|all|NUMERIC VALUE} # protocol
        --action {ACCEPT|REJECT|DROP|MARK|NOTRACK} # target of this entry, DNAT by default.
        -S # don't restart service
Example:
    # allow dhcp request from GUEST zone.
    $0 set Allow_guest_DHCP --src-zone GUEST --dst-port 53 --proto udp --action ACCEPT
_HELP_
}

case "$1" in
    set) cmd="$1";;
    del) cmd="$1";;
    *) echo "unknown command $1";help;exit 1;;
esac
shift 1

echo 'Caller MUST ensure that ID is unique.'
id="$1"
shift 1

while [ -n "$1" ]; do
    case $1 in
        --src-zone) src_zone="$2";shift 2;;
        --dst-zone) dst_zone="$2";shift 2;;
        --src-ip) src_ip="$2";shift 2;;
        --dst-ip) dst_ip="$2";shift 2;;
        --src-port) src_port="$2";shift 2;;
        --dst-port) dst_port="$2";shift 2;;
        --src-mac) src_mac="$2";shift 2;;
        --proto) proto="$2";shift 2;;
        --action) target="$2";shift 2;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) echo "unknown option $1";help;exit 2;;
        *) break;;
    esac
done

_del_rule()
{
    uci get firewall.${id} >/dev/null 2>&1
    [ "$?" == 0 ] && uci delete firewall.${id}
}

set_rule()
{
    _del_rule

    if [ -n "$src_zone" ]; then
        case "$src_zone" in
            TRUSTED) src_zone_id='0';;
            UNTRUSTED) src_zone_id='1';;
            DMZ) src_zone_id='2';;
            GUEST) src_zone_id='3';;
            *) echo "unknown src-zone $src_zone"; help; exit 3;;
        esac
    fi
    if [ -n "$dst_zone" ]; then
        case "$dst_zone" in
            TRUSTED) dst_zone_id='0';;
            UNTRUSTED) dst_zone_id='1';;
            DMZ) dst_zone_id='2';;
            GUEST) dst_zone_id='3';;
            *) echo "unknown dst-zone $dst_zone"; help; exit 4;;
        esac
    fi
    case "$target" in
        ACCEPT) target="$target";;
        REJECT) target="$target";;
        DROP) target="$target";;
        MARK) target="$target";;
        NOTRACK) target="$target";;
        *) echo "unknown action ${target}"; help; exit 5;;
    esac

    uci set firewall.${id}='rule'
    uci set firewall.${id}.name="${id}"
    [ -n "$src_zone" ] && uci set firewall.${id}.src="${src_zone}"
    [ -n "$dst_zone" ] && uci set firewall.${id}.dest="${dst_zone}"
    [ -n "$src_ip" ] && uci set firewall.${id}.src_ip="${src_ip}"
    [ -n "$dst_ip" ] && uci set firewall.${id}.dest_ip="${dst_ip}"
    [ -n "$src_port" ] && uci set firewall.${id}.src_port="${src_port}"
    [ -n "$dst_port" ] && uci set firewall.${id}.dest_port="${dst_port}"
    [ -n "$src_mac" ] && uci set firewall.${id}.src_mac="${src_mac}"
    [ -n "$proto" ] && uci set firewall.${id}.proto="${proto}"
    [ -n "$target" ] && uci set firewall.${id}.target="${target}"
}


del_rule()
{
    echo "Remove firewall rule <${id}>"
    _del_rule
}

case "$cmd" in
    set) set_rule;;
    del) del_rule;;
    *) help;exit 6;;
esac

uci commit firewall


if [ -z "$no_restart" ]; then
    /etc/init.d/firewall reload
fi

exit 0