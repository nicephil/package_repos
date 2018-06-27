#!/bin/sh

# 0. include modules

. /lib/functions.sh
. /lib/functions/network.sh
. /usr/share/libubox/jshn.sh

json_select_array() {
	local _json_no_warning=1

	json_select "$1"
	[ $? = 0 ] && return

	json_add_array "$1"
	json_close_array

	json_select "$1"
}

json_select_object() {
	local _json_no_warning=1

	json_select "$1"
	[ $? = 0 ] && return

	json_add_object "$1"
	json_close_object

	json_select "$1"
}

# 0.1 args
arg1="$1"
arg2="$2"


# 1. read config
config_load capwapc
config_get mas_server server mas_server
if [ -z "$mas_server" ]
then
    echo "failed: get mas_server"
    exit
fi

config_load productinfo
config_get mac productinfo mac
if [ -z "$mac" ]
then
    echo "failed: get mac"
    exit
fi

# $1 - cpuload name
# $2 - memoryinfo name
get_cpumem_info()
{
    local vname_cpu_load="$1"
    local vname_mem_info="$2"
    local topinfo="`top -n1 -d1`"
    local cpu_load=$(echo "$topinfo"| awk '{
        if (match($1, "CPU:")) {
            a=substr($8,1,length($8)-1);
            printf "%d",100-a
            exit
        }
    }')

    local mem_info=$(echo "$topinfo"|awk '{
        if (match($1, "Mem:")) {
            a=substr($2,1,length($2)-1)
            b=substr($4,1,length($4)-1)
            t=(a+b)
            v=(a/t)*100
            printf "%d_%d",t,v
            exit
        }
    }')


    unset "$vname_cpu_load"
    export "$vname_cpu_load=$cpu_load"
    unset "$vname_mem_info"
    export "$vname_mem_info=$mem_info"
}

generate_cpumemjson()
{
    local vname="$1"
    local cpuinfo="`cat /proc/cpuinfo`"
    local cpus=$(echo "$cpuinfo"|awk '{
        if (match($1, "processor")) {
            a ++;
        }
    }
    END {
        print a;
    }
    ')
    local cpu_frequency=$(echo "$cpuinfo"|awk '/BogoMIPS/{print $3;exit}')

    local cpu_load1=""
    local mem_info1=""
    local mem_load1=""
    get_cpumem_info cpu_load1 mem_info1
    OIFS=$IFS;IFS='_';set -- $mem_info1;mem_total=$1;mem_load1=$2;IFS=$OIFS
    sleep 1

    local cpu_load2=""
    local mem_info2=""
    local mem_load2=""
    get_cpumem_info cpu_load2 mem_info2
    OIFS=$IFS;IFS='_';set -- $mem_info2;mem_load2=$2;IFS=$OIFS
    sleep 2

    local cpu_load3=""
    local mem_info3=""
    local mem_load3=""
    get_cpumem_info cpu_load3 mem_info3
    OIFS=$IFS;IFS='_';set -- $mem_info3;mem_load3=$2;IFS=$OIFS
    local cpu_load=$((($cpu_load1+$cpu_load2+$cpu_load3)/3))
    local mem_load=$((($mem_load1+$mem_load2+$mem_load3)/3))

    local mem_type="DDR2"
    local mem_frequency="440"

    json_init
    json_add_int cpus "$cpus"
    json_add_string cpu_frequency "${cpu_frequency}MHz"
    json_add_int cpu_load "$cpu_load"
    json_add_string mem_total "${mem_total}K"
    json_add_string mem_type "$mem_type"
    json_add_string mem_frequency "${mem_frequency}MHz"
    json_add_int mem_load "$mem_load"

    export "${vname}=$(json_dump)"
    return 0
}


generate_chscanningjson()
{
    local vname="$1"
    local radio="$arg1"
    local disabled="$arg2"

    local ch_usabs="$(awk -F',' '{if(match($54,/[0-9]+/))print $2"_"$54;}' /tmp/icmseldebug_$radio.csv )"

    if [ "$radio" = "0" ]
    then
        local _2ch_nums="$(iwlist ath50 scanning 2>&1 | awk '/Channel/{key=substr($4,1,length($4)-1);sum[key]++;}END{for(k in sum)print k"_"sum[k];}')"
    fi
    if [ "$radio" = "1" ]
    then
        local _5ch_nums="$(iwlist ath60 scanning 2>&1 | awk '/Channel/{key=substr($4,1,length($4)-1);sum[key]++;}END{for(k in sum)print k"_"sum[k];}')" 
    fi

    echo "-------------->$ch_usabs" | logger -t 'devstats'
    echo "==============>$_2ch_nums"  | logger -t 'devstats'
    echo "-------------->$_5ch_nums" | logger -t 'devstats'

    if [ "$disabled" = "1" ]
    then
        uci set wireless.wifi$radio.disabled=1
        uci commit wireless
        wifi down wifi$radio
    fi


    json_init
    json_add_int radio "$radio"
    json_select_array 'list'

    # 2.4G
    if [ "$radio" = "0" ]
    then
    for i in `seq 1 1 13`
    do
        json_add_object
        json_add_int channel "$i"
        local has_2num=""
        local has_usab=""

        for _2ch_num in $_2ch_nums
        do
            OIFS=$IFS;IFS='_';set -- $_2ch_num;__2ch=$1;__2num=$2;IFS=$OIFS
            if [ "$__2ch" = "$i" ]
            then
                json_add_int ssid_number "$__2num"
                has_2num="1"
            fi
        done

        if [ -z "$has_2num" ]
        then
            json_add_int ssid_number "0"
        fi

        for ch_usab in $ch_usabs
        do
            OIFS=$IFS;IFS='_';set -- $ch_usab;__ch=$1;__usab=$2;IFS=$OIFS
            if [ "$__ch" = "$i" ]
            then
                json_add_int use_value "$__usab"
                has_usab="1"
            fi
        done

        if [ -z "$has_usab" ]
        then
            json_add_int use_value "0"
        fi

        json_close_object
    done
    fi

    # 5G
    if [ "$radio" = "1" ]
    then
    for ch_usab in $ch_usabs
    do
        local has_num=""

        OIFS=$IFS;IFS='_';set -- $ch_usab;__ch=$1;__usab=$2;IFS=$OIFS

        if [ "$__ch" -lt "13" ]
        then
            continue
        fi

        json_add_object
        json_add_int channel "$__ch"

        for _5ch_num in $_5ch_nums
        do
            OIFS=$IFS;IFS='_';set -- $_5ch_num;__5ch=$1;__5num=$2;IFS=$OIFS
            if [ "$__5ch" = "$__ch" ]
            then
                json_add_int ssid_number "$__5num"
                has_num="1"
            fi
        done

        if [ -z "$has_num" ]
        then
            json_add_int ssid_number "0"
        fi
        
        json_add_int use_value "$__usab"

        json_close_object
    done
    fi

    json_select ..

    export "$vname=$(json_dump)"
    return 0
}

generate_radtestjson()
{
    local vname="$1"
    # echo "has_radtestjson=1 has_cookie=$cookie server=$server port=$port username=$username password=$password /lib/okos/devstats.sh"
    local _code="0"
    local _msg="success"

    #1. ping it
    ping -w 3 $server > /dev/null 2>&1
    if [ "$?" != "0" ]
    then
        _code="1"
        _msg="ping gets no response"
    else 
        #2. nc port
        nc -zuv $server $port > /dev/null 2>&1
        if [ "$?" != "0" ]
        then
            _code="2"
            _msg="ping ok, but port not opened"
        else
            #3. radtest with user and password
            :
        fi
    fi

    json_init
    json_add_int code "$_code"
    json_add_string msg "$_msg"
    unset "${vname}"
    export "${vname}=$(json_dump)"
    return 0
}




# 2. process
has_cpumemjson=${has_cpumemjson:=0}
if [ "$has_cpumemjson" ]
then
    generate_cpumemjson cpumemjson
fi

if [ "$has_chscanningjson" ]
then
    generate_chscanningjson chscanningjson
fi

if [ "$has_radtestjson" ]
then
    generate_radtestjson radtestjson
fi

# 3. final json data
json_init
json_select_array "list"

if [ "$has_cpumemjson" = "1" ]
then
    json_add_object
    json_add_int operate_type "12"
    json_add_string mac "$mac"
    json_add_string cookie_id "$has_cookie"
    json_add_string data "$cpumemjson"
    json_close_object
fi

if [ "$has_chscanningjson" = "1" ]
then
    json_add_object
    json_add_int operate_type "16"
    json_add_string mac "$mac"
    json_add_string cookie_id "$has_cookie"
    json_add_string data "$chscanningjson"
    json_close_object
fi

if [ "$has_radtestjson" = "1" ]
then
    json_add_object
    json_add_int operate_type "10000"
    json_add_string mac "$mac"
    json_add_string cookie_id "$has_cookie"
    json_add_string data "$radtestjson"
    json_close_object
fi



json_select ..

json_data=$(json_dump)

echo $json_data | logger -p user.info -t '01-SYSTEM-LOG'
#echo $json_data

# 4. upload json file to nms
URL="http://${mas_server}/nms/api/device/ap/info"
curl -m 120 -i -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL
