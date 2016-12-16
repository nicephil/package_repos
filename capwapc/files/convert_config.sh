#!/bin/sh

. /lib/functions.sh

buffer=""

config_cb() {
    local type="$1"
    local name="$2"
    if [ "$name" == "server" ]
    then
        append buffer "<AC_ADDRESS>\n"
        option_cb() {
            local name="$1"
            local value="$2"
            append buffer "</AC_ADDRESS>$value\n"
        }
    elif [ "$name" == "wtp" ]
    then
        option_cb() {
            local name="$1"
            local value="$2"
            case "$name" in
                "ctrl_port")
                append buffer "</WTP_CTRL_PORT>$value\n"
                ;;
                "mtu")
                append buffer "</WTP_FORCE_MTU>$value\n"
                ;;
                "disc_intv")
                append buffer "</WTP_DISC_INTV>$value\n"
                ;;
                "maxdisc_intv")
                append buffer "</WTP_MAXDISC_INTV>$value\n"
                ;;
                "echo_intv")
                append buffer "</WTP_ECHO_INTV>$value\n"
                ;;
                "retran_intv")
                append buffer "</WTP_RETRAN_INTV>$value\n"
                ;;
                "silent_intv")
                append buffer "</WTP_SILENT_INTV>$value\n"
                ;;
                "join_timeout")
                append buffer "</WTP_JOIN_TIMEOUT>$value\n"
                ;;
                "max_disces")
                append buffer "</WTP_MAX_DISCES>$value\n"
                ;;
                "max_retran")
                append buffer "</WTP_MAX_TRANS>$value\n"
                ;;
                *)
                echo "error: not support"
                ;;
            esac
                
        }
    fi
}


main () {
    config_load capwapc
    echo -e $buffer
}

main

