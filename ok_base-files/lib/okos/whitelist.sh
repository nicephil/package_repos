#!/bin/sh

CMD="iptables"
CHAIN="WhiteList"

start ()
{
    $CMD -S $CHAIN > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "$CHAIN is already exist."
    else
        echo "Create chain ${CHAIN} ."
        $CMD -N $CHAIN
    fi

    $CMD -S FORWARD | grep $CHAIN
    if [ $? -eq 0 ]; then
        echo "${CHAIN} has been already added into FORWARD Chain. No action."
    else
        basic_rule=`$CMD -L FORWARD --line-number | grep "RELATED" | grep "ESTABLISHED" | grep "ACCEPT"`
        if [ -z "${basic_rule}" -o $? -ne 0 ]; then
            echo "Can not find basic FORWARD rule, Insert WhiteList into the head of FORWARD Chain."
            pos=1
        else
            echo "Find basic FORWARD rule, attach WhiteList after it."
            i=`echo $basic_rule | awk '{print $1}'`
            pos=$(( i + 1 ))
            #pos=2
        fi
        echo "Add WhiteList to position $pos ."
        $CMD -I FORWARD $pos -j $CHAIN
    fi
}

stop ()
{
    while [ true ]; do
        $CMD -S FORWARD | grep $CHAIN
        if [ $? -eq 0 ]; then
            echo "Delete the rule jumping to $CHAIN ."
            $CMD -D FORWARD -j $CHAIN
        else
            break
        fi
    done

    while [ true ]; do
        $CMD -S $CHAIN > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "Flush chain $CHAIN and delete it."
            $CMD -F $CHAIN
            $CMD -X $CHAIN
        else
            break
        fi
    done
}

add ()
{
    local _mac_=$1
    $CMD -S $CHAIN > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Chain $CHAIN has never been installed. Create it now."
        start
    fi

    $CMD -S $CHAIN | grep -i $_mac_
    if [ $? -eq 0 ]; then
        echo "Client has been already exist."
    else
        echo "Add new client ${_mac_} ."
        $CMD -A $CHAIN -m mac --mac-source $_mac_ -j ACCEPT
    fi
}

del ()
{
    local _mac_=$1
    while [ true ]; do
        $CMD -S $CHAIN | grep -i $_mac_ > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "Delete client $_mac_ ."
            $CMD -D $CHAIN -m mac --mac-source $_mac_ -j ACCEPT
        else
            break
        fi
    done
}

show ()
{
    $CMD -S $CHAIN
}

case "$1" in
    start)
        start
        ;;
    restart)
        stop
        start
        ;;
    stop)
        stop
        ;;
    add)
        [ -z "$2" ] && echo "Usage: $0 $1 mac" && exit 1
        add $2
        ;;
    del)
        [ -z "$2" ] && echo "Usage: $0 $1 mac" && exit 1
        del $2
        ;;
    show)
        show
        ;;
    *)
        echo "Usage: $0 [restart|start|stop|add|del|show]" && exit 1
        ;;
esac
