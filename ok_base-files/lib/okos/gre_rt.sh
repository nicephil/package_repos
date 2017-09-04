#!/bin/sh
################################################################################
# This script is used to setup gre tunnel between router and APs to construct
# a tunnel for our `guest` network.
# Especially, on gateway side, we use the router, but not an AP as a gateway.
# So, no more wireless network should be considered on gateway side.
################################################################################

. ./gre.sh

case "$1" in
    start)
        start_router
        ;;
    stop)
        stop_router
        ;;
    restart)
        stop_router
        start_router
        ;;
    add)
        shift 1
        [ $# != 1 ] && echo "$0 add xxx.xxx.xxx.xxx" && exit 1
        add_on_router $1
        ;;
    *)
        echo "Usage:"
        echo "    $0 [start|stop|restart|add]"
        exit 1
        ;;
esac

