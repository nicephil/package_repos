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
    local topinfo="`top -n1 -b`"
    local cpu_load=$(echo "$topinfo"| awk '{
        if (match($1, "CPU:")) {
            a=substr($8,1,length($8)-1);
            print 100-a;
        }
    }')

    local mem_info=$(echo "$topinfo"|awk '{
        if (match($1, "Mem:")) {
            a=substr($2,1,length($2)-1)
            b=substr($4,1,length($4)-1)
            t=(a+b)
            v=(a/t)*100
            print t"_"v;
        }
    }')

    OIFS=$IFS;IFS='_';set -- $mem_info;mem_total=$1;mem_load=$2;IFS=$OIFS
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

    local ch_usabs="$(awk -F',' '{if(match($54,/[0-9]+/))print $2"_"$54;}' /tmp/icmseldebug.csv )"

    killall icm

    local _2ch_nums="$(iwlist ath50 scanning 2>&1 | awk '/Channel/{key=substr($4,1,length($4)-1);sum[key]++;}END{for(k in sum)print k"_"sum[k];}')"
    local _5ch_nums="$(iwlist ath60 scanning 2>&1 | awk '/Channel/{key=substr($4,1,length($4)-1);sum[key]++;}END{for(k in sum)print k"_"sum[k];}')" 

    #echo "-------------->$ch_usabs" | logger -t 'devstats'
    #echo "==============>$_2ch_nums" | logger -t 'devstats'
    echo "-------------->$_5ch_nums" | logger -t 'devstats'


    json_init
    json_select_array "list"

    # 2.4G
    if [ -n "$_2ch_nums" ]
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
    if [ -n "$_5ch_nums" ]
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

# 3. final json data
json_init
json_select_array "list"

if [ "$has_cpumemjson" = "1" ]
then
    json_add_object
    json_add_int operate_type "12"
    json_add_string mac "$mac"
    json_add_string data "$cpumemjson"
    json_close_object
fi

if [ "$has_chscanningjson" = "1" ]
then
    json_add_object
    json_add_int operate_type "16"
    json_add_string mac "$mac"
    json_add_string data "$chscanningjson"
    json_close_object
fi

json_select ..

json_data=$(json_dump)

# echo $json_data | logger -t 'devstats'

# 4. upload json file to nms
URL="http://${mas_server}/nms/api/device/ap/info"
curl -i -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL
