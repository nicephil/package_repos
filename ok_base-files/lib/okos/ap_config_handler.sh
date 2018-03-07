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
        echo $@ | logger -p 7 -t 'ap_config'
    fi
}

config_log_info()
{
    if [ -n "$DEBUG" ]
    then
        echo "ap_config: $@"
    else
        echo $@ | logger -s -p 5 -t 'ap_config'
    fi
}

config_log_err()
{
    if [ -n "$DEBUG" ]
    then
        echo "ap_config: $@"
    else
        echo $@ | logger -s -p 3 -t 'ap_config'
    fi
}

# 0. global variable
old_file="/tmp/old_config.json"
new_file="/tmp/new_config.json"
cfgdiff="/lib/okos/cfgdiff.py"
ret=0

# 1. save new config
echo $json_data > $new_file

# 2. any old config here?
if [ -f "$old_file" ] 
then
    $cfgdiff $new_file -o $old_file
    ret=$?
    config_log_err "---cfgdiff:$ret"
else
    ret=1
fi

mv $new_file $old_file

return $ret 
