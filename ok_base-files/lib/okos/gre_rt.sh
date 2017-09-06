#!/bin/sh
################################################################################
# This script is used to setup gre tunnel between router and APs to construct
# a tunnel for our `guest` network.
# Especially, on gateway side, we use the router, but not an AP as a gateway.
# So, no more wireless network should be considered on gateway side.
################################################################################

. $( dirname $0 )/gre.sh

test ()
{
    local i=1
    while [ $i -lt 200 ]; do
        i=$(( $i + 1 ))
        add_on_router 172.16.15.$i
    done
}

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
    test)
        test
        ;;
    *)
        echo "Usage:"
        echo "    $0 [start|stop|restart|add]"
        exit 1
        ;;
esac

