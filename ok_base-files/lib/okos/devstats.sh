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

# 2. process
has_cpumemjson=${has_cpumemjson:=0}
if [ "$has_cpumemjson" ]
then
    generate_cpumemjson cpumemjson
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

json_select ..

json_data=$(json_dump)

echo $json_data

# 4. upload json file to nms
URL="http://${mas_server}/nms/api/device/ap/info"
curl -i -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$json_data" $URL
