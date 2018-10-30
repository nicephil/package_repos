#!/bin/sh

help()
{
    cat <<_HELP_
Setup/Remove site to site vpn
Usage: $0 {set|del} ID {OPTIONS} [-S]
       $0 del ID --remote-subnet IPADDR/NETMASK [-S]
       $0 set ID --remote-subnet IPADDR/NETMASK --local IPADDR --remote IPADDR --psk STRING
            [--ikev VERSION] [--encryption ALGORITHM] [--hash ALGORITHM] [--dh GROUP] 
            [-S]

        ID # use ID to identify each site to site vpn entry. 
           # Caller MUST ensure it's unique.
           # used as mark of fwmark
           # must be numberic
        --local IPADDR # local identifier for phase 1
        --remote IPADDR # IP address or FQDN name of the tunnel remote endpoint.
                        # remote identifier for phase 1
        --ikev {*ikev1|ikev2} # key exchange version
        --psk STRING # The preshared key for the tunnel if authentication is psk
        --encryption {*aes128|aes192|aes256|3des} # Phase 1 encryption method
        --hash {*sha1|md5} # Phase 1 hash alogrithm
        --dh {2|5|*14|15|16|19|20|21|25|26} # Diffie-Hellman exponentiation
        --remote-subnet IPADDR/NETMASK[,IPADDR/NETMASK] # Remote network eg. 10.1.10.0/23
        -R # remove this configuration by ID
        -S # don't restart service, just remove the config.
Example:
    # set up site to site vpn with hanhai.
    $0 set 101 --local 223.93.139.132 --remote 68.121.161.25 --psk iahnah --remote-subnet 10.1.10.0/23
    # remove site to site vpn to hanhai
    $0 del 101 --remote-subnet 10.1.10.0/23
_HELP_
}

if [ $# -lt 2 ]; then
    help
    exit 1
fi

cmd="$1"
echo 'Caller MUST ensure that ID is unique and numberic.'
id="$2"
site_name="s_$id"
tunnel_name="t_$id"
shift 2

ikev_set='ikev1 ikev2'
encryption_set='aes128 aes192 aes256 3des'
hash_set='sha1 md5'
dh_set='modp768 modp1024 modp2048'
dh_set='2 5 14 15 16 19 20 21 25 26'

ikev='ikev1'
encryption='aes128'
hash='sha1'
dh='14'
while [ -n "$1" ]; do
    case $1 in
        --local) local_ip="$2";shift 2;;
        --remote) remote_ip="$2";shift 2;;
        --ikev) ikev="$2";shift 2;;
        --psk) psk="$2";shift 2;;
        --encryption) encryption="$2";shift 2;;
        --hash) hash="$2";shift 2;;
        --dh) dh="$2";shift 2;;
        --remote-subnet) remote_subnets="$2";shift 2;;
        -R) remove='yes';shift 1;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done
[ -z "$remote_subnets" ] && help && exit 1

# cleanup ipsec config in uci
uci get ipsec.${site_name} >/dev/null 2>&1
[ "$?" == 0 ] && uci del ipsec.${site_name}
uci get ipsec.${tunnel_name} >/dev/null 2>&1
[ "$?" == 0 ] && uci del ipsec.${tunnel_name}
uci get ipsec.${crypto} >/dev/null 2>&1
[ "$?" == 0 ] && uci del ipsec.${crypto}

if [ "$cmd" = 'set' ]; then
    case "$ikev" in
        ikev1) ikev=$ikev;;
        ikev2) ikev=$ikev;;
        *) help; exit 1;;
    esac
    case "$encryption" in
        aes128) encryption=$encryption;;
        aes192) encryption=$encryption;;
        aes256) encryption=$encryption;;
        3des) encryption=$encryption;;
        *) help; exit;;
    esac
    case "$hash" in
        sha1) hash=$hash;;
        md5) hash=$hash;;
        *) help; exit 1;;
    esac
    case "$dh" in
        2) dh="modp1024";;
        5) dh="modp1536";;
        14) dh="modp2048";;
        15) dh="modp3072";;
        16) dh="modp4096";;
        19) dh="ecp256";;
        20) dh="ecp384";;
        21) dh="ecp521";;
        25) dh="ecp192";;
        26) dh="ecp224";;
        *) help; exit 1;;
    esac
    crypto_name="c_${encryption}_${hash}_${dh}"

    [ -z "$local_ip" -o -z "$remote_ip" -o -z "$psk" ] && help && exit 1
    local_nat_ip=$(ip r get ${remote_ip} | sed '1 s/[0-9.]* *via *[0-9.]* *dev *eth[0-9] *src *\([0-9a-z. ]*\)$/\1/p' -n)
    [ -z "$local_nat_ip" ] && echo "No route to ${remote_ip} found" && exit 1

    echo "Setup site to site vpn ${id} from ${local_ip} to ${remote_ip} via ${local_nat_ip}"
    uci set ipsec.${site_name}='remote'
    uci set ipsec.${site_name}.gateway="${remote_ip}"
    uci set ipsec.${site_name}.remote_identifier="${remote_ip}"
    uci set ipsec.${site_name}.local_identifier="${local_ip}"
    uci set ipsec.${site_name}.authentication_method="psk"
    uci set ipsec.${site_name}.pre_shared_key="${psk}"
    uci add_list ipsec.${site_name}.crypto_proposal="${crypto_name}"
    uci set ipsec.${site_name}.force_crypto_proposal='1'
    uci add_list ipsec.${site_name}.tunnel="${tunnel_name}"
    uci set ipsec.${tunnel_name}='tunnel'
    uci set ipsec.${tunnel_name}.mode='start'
    uci set ipsec.${tunnel_name}.mark="${id}"
    uci set ipsec.${tunnel_name}.keyexchange="${ikev}"
    uci set ipsec.${tunnel_name}.local_subnet="0.0.0.0/0"
    uci set ipsec.${tunnel_name}.remote_subnet="0.0.0.0/0"
    #uci set ipsec.${tunnel_name}.remote_subnet="${remote_subnets}"
    uci set ipsec.${tunnel_name}.updown="/lib/okos/bin/site_to_site_vpn_updown.sh ${remote_subnets}"
    uci set ipsec.${tunnel_name}.crypto_proposal="${crypto_name}"
    uci set ipsec.${tunnel_name}.force_crypto_proposal='1'
    uci set ipsec.${crypto_name}='crypto_proposal'
    uci set ipsec.${crypto_name}.encryption_algorithm="${encryption}"
    uci set ipsec.${crypto_name}.hash_algorithm="${hash}"
    uci set ipsec.${crypto_name}.dh_group="${dh}"
    uci set ipsec.${site_name}.enabled='1'


elif [ "$cmd" = 'del' ]; then
    echo "Remove site to site vpn: ${id}"
#    ip route del ${remote_subnet} dev ${tunnel_name} scope link
#    ip tunnel del ${tunnel_name}
else
    help
    exit 1
fi
uci commit ipsec

if [ -z "$no_restart" ]; then
    echo 'restart ipsec'
    /etc/init.d/ipsec restart
fi

#if [ "$cmd" = 'set' ]; then
#    echo "ip tunnel add ${tunnel_name} remote ${remote_ip} local ${local_nat_ip} mode vti key ${id}"
#    ip tunnel add ${tunnel_name} remote ${remote_ip} local ${local_nat_ip} mode vti key ${id}
#    echo "ip link set ${tunnel_name} up"
#    ip link set ${tunnel_name} up
#    echo "ip route add ${remote_subnet} dev ${tunnel_name} scope link"
#    ip route add ${remote_subnet} dev ${tunnel_name} scope link
#fi

exit 0
