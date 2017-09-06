#!/bin/sh

. $( dirname $0 )/gre.sh

case "$1" in
    start)
        shift 1
        start_ap
        ;;
    stop)
        shift 1
        stop_ap
        ;;
    restart)
        stop_ap
        start_ap
        ;;
    add)
        add_on_ap
        ;;
    *)
        echo "Usage:$0 [start|stop|restart|add]"
        exit 1
        ;;
esac

