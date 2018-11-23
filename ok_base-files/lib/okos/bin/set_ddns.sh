#!/bin/sh

################################################################################
# Tricky of ddns service:
# 1) For start/stop/restart: shell script will read configuration from uci at
#    first, then do start/stop according to the section ID in uci config. So,
#    It could NOT kill processes which removed previously from uci.
# 2) When using reload, reload will send signal 1 to all the daemons to restart
#    them. But, unforturnately, it won't load the configuration from uci newly
#    added.
#
# So, if you are trying to delete a ddns entry, you have to stop service, remove
# configure section from uci, then start all the sections again.
# If you are adding some new, you can stop them firstly, add something new, then
# start them all; or you can add new entries to uci, then restrat service.
#
# Important!
# Trying to restart service in postrun of config process is useless!!!
# Remove '-S' option from python!
# 

help()
{
    cat <<_HELP_
Setup/Remove DDNS

Usage:  $0 {set|del|stat|updatetime} ID [--provider PROVIDER] [--username STRING] [--password STRING]
                        [--domainname STRING] [--interface INTERFACE] [-S]
                        [--ipaddr x.x.x.x]
        $0 del ID
        $0 stat ID [--domainname STRING] [--ipaddr x.x.x.x]
        $0 updatetime ID
        $0 set ID [--provider PROVIDER] [--username STRING] [--password STRING]
                  [--domainname STRING] [--interface INTERFACE] [-S]
                  [--ipaddr x.x.x.x]

        ID # use ID to identify each ddns configure entry. 
           # Caller MUST ensure it's unique.
        --provider {oray.com|3322.org|zoneedit.com|no-ip.com}
        --domainname STRING # The DNS/host name to update, this name must already be registered with the DDNS provider.
        --interface {wan|wan1|wan2}
        --username STRING # Username of your DDNS providers account
        --password STRING # Password of your DDNS providers account
        --ipaddr x.x.x.x # IP Address corresponding to you DOMAIN NAME.
        -S # don't restart service
Example:
    $0 set 101 --provider 3322.org --domainname ak74.f3322.net --username root --password wangleih --interface wan --ipaddr 192.168.254.171
    $0 del 101
    $0 set 101 --provider oray.com --domainname ak74.f3322.net --username root --password wangleih --interface wan --ipaddr 192.168.254.171
    $0 set 101 --provider zoneedit.com --domainname nicephil.oakridge.vip --username nicephil --password AE7889603A021CE0 --interface wan --ipaddr 192.168.254.171
    $0 set 2 --provider 3322.org --domainname largepuppet.f3322.net --username root --password largepuppet --interface wan --ipaddr 223.93.139.132
_HELP_
}

case "$1" in
    set) cmd="$1";;
    del) cmd="$1";;
    stat) cmd="$1";;
    updatetime) cmd="$1";;
    *) help;exit 1;;
esac
shift 1

#echo 'Caller MUST ensure that ID is unique.'
id="$1"
shift 1

while [ -n "$1" ]; do
    case $1 in
        --provider) provider="$2";shift 2;;
        --domainname) domainname="$2";shift 2;;
        --interface) interface="$2";shift 2;;
        --username) username="$2";shift 2;;
        --password) password="$2";shift 2;;
        --ipaddr) ipaddr="$2";shift 2;;
        -S) shift 1;;
        --) shift;break;;
        -*) help;exit 1;;
        *) break;;
    esac
done

#echo "parameter parsed successfully"

_del_ddns()
{
    #echo "remove ${id}"
    uci get ddns.${id} >/dev/null 2>&1
    [ "$?" == 0 ] && uci del ddns.${id}
}

add_ddns()
{
    _del_ddns

    [ -z "${provider}" -o -z "${domainname}" -o -z "${username}" -o -z "${password}" ] && help && exit 1
    #echo "checking ${provider}"
    case "${provider}" in
        oray.com) ip_url="http://ddns.oray.com/checkip";update_url="http://[USERNAME]:[PASSWORD]@ddns.oray.com/ph/update?hostname=[DOMAIN]&myip=[IP]";;
        3322.org) service="$provider";ip_url="http://ip.3322.org";;
        zoneedit.com) service="$provider";ip_url="http://wtfismyip.com/text";;
        no-ip.com) service="$provider";;
        *) help;exit 1;;
    esac

    echo "Add ddns entry ${domainname} on ${provider}"
    uci set ddns.${id}='service'
    uci set ddns.${id}.enabled='1'
    uci set ddns.${id}.domain="$domainname"
    uci set ddns.${id}.username="$username"
    uci set ddns.${id}.password="$password"
    uci set ddns.${id}.interface="$interface"
    uci set ddns.${id}.ipaddr="$ipaddr"
    uci set ddns.${id}.allow_local_ip='1'
    uci set ddns.${id}.upd_privateip='1'
    uci set ddns.${id}.use_logfile='1'
    uci set ddns.${id}.ip_source='script'
    uci set ddns.${id}.ip_script="/lib/okos/bin/ddns_ip_script.sh ${ipaddr}"
#    if [ -z "$interface" ]; then
#        uci set ddns.${id}.ip_source='web'
#        uci set ddns.${id}.ip_url="$ip_url"
#    else
#        uci set ddns.${id}.ip_source='network'
#        uci set ddns.${id}.ip_network="$interface"
#    fi
    if [ -z "$service" ]; then
        uci set ddns.${id}.update_url="$update_url"
    else
        uci set ddns.${id}.service_name="$service"
    fi

    /etc/init.d/ddns restart
}

del_ddns()
{
    echo "Remove ddns entry <${id}>"
    /etc/init.d/ddns stop
    _del_ddns
    /etc/init.d/ddns start
}

stat_ddns()
{
    egrep "good|nochg" /var/run/ddns/${id}.dat > /dev/null 2>&1
    [ "$?" == 0 ] && {
        echo 'success'
        exit 0
    }
    [ -n "$ipaddr" ] && {
        egrep "${ipaddr}" /var/run/ddns/${id}.dat > /dev/null 2>&1
        [ "$?" == 0 ] && {
            echo 'success'
            exit 0
        }
    }

    echo 'fail'
    exit 0
}

update_time()
{
    local last_time=$(cat /var/run/ddns/${id}.update)
    local _uptime=$(cat /proc/uptime)
    local up_time=${_uptime%%.*}
    local epoch_time=$(( $up_time - $last_time ))
    echo "${epoch_time} seconds ago"
    exit 0
}
case "$cmd" in
    set) add_ddns;;
    del) del_ddns;;
    stat) stat_ddns;;
    updatetime) update_time;;
    *) help;exit 1;;
esac
uci commit ddns


exit 0

