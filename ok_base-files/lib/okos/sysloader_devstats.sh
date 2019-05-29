#!/bin/sh

# 0. include modules

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

# $1 - state
# $2 - error_message
report_status() {
    _state="$1"
    _error_message="$2"

    # 1. read config
    config_load capwapc
    config_get mas_server server mas_server
    if [ -z "$mas_server" ]
    then
        echo "failed: get mas_server"
        return
    fi
    config_get oakmgr_pub_port image oakmgr_pub_port
    [ -z "$oakmgr_pub_port" ] && oakmgr_pub_port="80"

    config_load productinfo
    config_get mac productinfo mac
    if [ -z "$mac" ]
    then
        echo "failed: get mac"
        return
    fi
    config_get production productinfo model
    if [ -z "$production" ]
    then
        echo "failed: get production"
        return
    fi

    # 2. internal json data
    json_init
    json_add_int state "$_state"
    json_add_string product_name "$production"
    json_add_string error_message "$_error_message"
    devstatsjson=$(json_dump)
    echo $devstatsjson | logger -t 'devstats'

    # 3. final json data
    json_init
    json_select_array "list"

    json_add_object
    json_add_int operate_type "1000"
    json_add_string mac "$mac"
    json_add_string data "$devstatsjson"
    json_close_object

    json_select ..

    _json_data=$(json_dump)

    echo $_json_data | logger -t 'devstats'

    # 4. upload json file to nms
    URL="http://${mas_server}:${oakmgr_pub_port}/nms/api/device/ap/info"
    curl -i -X POST -H "Content-type: application/json" -H "charset: utf-8" -H "Accept: */*" -d "$_json_data" $URL
}
