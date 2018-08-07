#!/bin/sh
. /usr/share/libubox/jshn.sh

case "$1" in
    list)
        echo '{"status":{"site":"www.baidu.com"}}'
        ;;
    call)
        case "$2" in
            status)
                # read the arguments
                read input;
                # optionally log the status
                logger -t "ping_mgr" "$2" "$input"
                # return json object or an array
                json_init
                json_load "$input"
                json_get_vars site
                logger -t "ping_mgr" "$2, $site"
                result=$(ping -c2 -w3 "$site" 2>&1 | awk -F '[/ ]+' '/round-trip/{print $7;exit;}')
                [ -z "$result" ] && result="0"
                echo "{\"site\":\"$site\", \"result\":\"$result\"}"
                ;;
        esac
        ;;
esac
