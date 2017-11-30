#!/bin/sh

DEBUG="$1"
[ -n "$DEBUG" ] && {
    # cpumem info
    export 'json_data={"data":"","operate_type":12}'
    # channel scanning
    # export 'json_data={"data":"","operate_type":16}'
    # config channel
    # export 'json_data={"data":"","operate_type":17}'
}

config_log()
{
    if [ -n "$DEBUG" ]
    then
        echo "new_config: $@"
    else
        logger -t 'new_config' $@
    fi
}

. /usr/share/libubox/jshn.sh
. /lib/functions.sh

# json_data env
json_init
json_load "$json_data"

operate_type=""
data=""
json_get_vars operate_type data

config_log "$operate_type" "$data"

handle_cpumeminfo()
{
    has_cpumemjson=1 /lib/okos/devstats.sh
    return 0
}

 handle_chscanning()
{
    return 0
}

 handle_setschan()
{
    return 0
}

case "$operate_type" in
    "12")
        if ! handle_cpumeminfo "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;

    "15")
        if ! handle_chscanning "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;

    "17")
        if ! handle_setchan "$operate_type" "$data"
        then
            config_log "$operate_type $data failed"
            return 1
        fi
        config_log "$operate_type $data success"
        return 0
        ;;
    *)
        config_log "unknown type $operate_type $data"
        return 1
        ;;
esac

return 0
