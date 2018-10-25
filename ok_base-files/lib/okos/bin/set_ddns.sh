#!/bin/sh

help()
{
    cat <<_HELP_
Setup/Remove DDNS

Usage: $0 ID [--provider PROVIDER] [--username STRING] [--password STRING]
            [--domainname STRING] [--interface INTERFACE] [-R] [-S]
        ID # use ID to identify each port mac ip address binding entry. 
           # Caller MUST ensure it's unique.
        --provider {oray.com|3322.org|zoneedit.com}
        --domainname STRING # The DNS/host name to update, this name must already be registered with the DDNS provider.
        --interface {wan|wan1|wan2}
        --username STRING # Username of your DDNS providers account
        --password STRING # Password of your DDNS providers account
        -R # remove this entry
        -S # don't restart service
Example:
    $0 101_1 --provider 3322.org --domainname oakridge.3322.org --username oakridge --password oakridge 
_HELP_
}

if [ $# -lt 1 ]; then
    help
    exit 1
fi

echo 'Caller MUST ensure that ID is unique.'
id="$1"
shift 1

while [ -n "$1" ]; do
    case $1 in
        --provider) provider="$2";shift 2;;
        --domainname) domainname="$2";shift 2;;
        --interface) interface="$2";shift 2;;
        --username) username="$2";shift 2;;
        --password) password="$2";shift 2;;
        -R) remove='yes';shift 1;;
        -S) no_restart='1';shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

case "${provider}" in
    oray.com) ip_url="http://ddns.oray.com/checkip";update_url="http://[USERNAME]:[PASSWORD]@ddns.oray.com/ph/update?hostname=[DOMAIN]&myip=[IP]";;
    3322.org) service="$provider";ip_url="http://ip.3322.org";;
    zoneedit.com) service="$provider";ip_url="http://wtfismyip.com/text";;
    *) help;exit 1;;
esac

uci get ddns.${id} >/dev/null 2&>1
if [ "$?" == 0 ]; then
    uci del ddns.${id}
fi

if [ -z "${remove}" ]; then
    [ -z "${provider}" -o -z "${domainname}" -o -z "${username}" -o -z "${password}" ] && help && exit 1
    echo "Add ddns entry ${domainname} on ${provider}"
    uci set ddns.${id}='service'
    uci set ddns.${id}.enable='1'
    uci set ddns.${id}.domain="$domainname"
    uci set ddns.${id}.username="$username"
    uci set ddns.${id}.password="$password"
    if [ -z "$interface" ]; then
        uci set ddns.${id}.ip_source='web'
        uci set ddns.${id}.ip_url="$ip_url"
    else
        uci set ddns.${id}.ip_source='network'
        uci set ddns.${id}.ip_network="$interface"
    fi
    if [ -z "$service" ]; then
        uci set ddns.${id}.update_url="$update_url"
    else
        uci set ddns.${id}.service_name="$service"
    fi
else
    echo "Remove ddns entry <${id}>"
fi

uci commit ddns

if [ -z "$no_restart" ]; then
    /etc/init.d/ddns restart
fi

exit 0

