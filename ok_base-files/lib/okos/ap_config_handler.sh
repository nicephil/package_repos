#!/bin/sh

DEBUG="$1"
[ -n "$DEBUG" ] && {
    # config info
    export 'json_data={"data":"{\"cpu_memory\":1}","operate_type":10001}'
}

config_log_debug()
{
    if [ -n "$DEBUG" ]
    then
        echo "ap_config: $@"
    else
        logger -p 7 -t 'ap_config' $@
    fi
}

config_log_info()
{
    if [ -n "$DEBUG" ]
    then
        echo "ap_config: $@"
    else
        logger -p 5 -t 'ap_config' $@
    fi
}

config_log_err()
{
    if [ -n "$DEBUG" ]
    then
        echo "ap_config: $@"
    else
        logger -p 3 -t 'ap_config' $@
    fi
}

. /usr/share/libubox/jshn.sh
. /lib/functions.sh

config_log_err "---xxxx:start"

# json_data env

echo $json_data > /tmp/new_config.json

config_log_err "---xxxx:end"
return 0
