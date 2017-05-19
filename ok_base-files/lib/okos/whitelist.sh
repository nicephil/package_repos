#!/bin/sh

CMD="iptables"
CHAIN="WhiteList"

start ()
{
    for t in filter nat; do
        $CMD -t $t -S $CHAIN > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "$CHAIN in table $t is already exist."
        else
            echo "Create chain ${CHAIN} on table ${t}."
            $CMD -t $t -N $CHAIN
        fi

        local basic_chain="FORWARD"
        if [ $t != "filter" ]; then
            basic_chain="PREROUTING"
        fi

        $CMD -t $t -S ${basic_chain} | grep $CHAIN
        if [ $? -eq 0 ]; then
            echo "${CHAIN} has been already added into table ${t}. No action."
        else
            local pos=1
            if [ $t == "filter" ]; then
                local basic_rule=`$CMD -t $t -L ${basic_chain} --line-number | grep "RELATED" | grep "ESTABLISHED" | grep "ACCEPT"`
                if [ ! -z "${basic_rule}" -a $? -eq 0 ]; then
                    echo "Find basic rule in talbe ${t}, attach WhiteList after it."
                    i=`echo $basic_rule | awk '{print $1}'`
                    pos=$(( i + 1 ))
                    #pos=2
                fi
            fi

            echo "Add WhiteList to position $pos on table ${t}."
            $CMD -t $t -I ${basic_chain} $pos -j $CHAIN
        fi
    done
}

stop ()
{
    for t in filter nat; do
        local basic_chain="FORWARD"
        if [ $t != "filter" ]; then
            basic_chain="PREROUTING"
        fi
        while [ true ]; do
            $CMD -t $t -S ${basic_chain} | grep $CHAIN
            if [ $? -eq 0 ]; then
                echo "Delete the rule jumping to $CHAIN ."
                $CMD -t $t -D ${basic_chain} -j $CHAIN
            else
                break
            fi
        done

        while [ true ]; do
            $CMD -t $t -S $CHAIN > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "Flush chain $CHAIN and delete it."
                $CMD -t $t -F $CHAIN
                $CMD -t $t -X $CHAIN
            else
                break
            fi
        done
    done
}

add ()
{
    local _mac_=$1
    for t in filter nat; do
        $CMD -t $t -S $CHAIN > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "Chain $CHAIN has never been installed. Create it now."
            start
        fi

        $CMD -t $t -S $CHAIN | grep -i $_mac_
        if [ $? -eq 0 ]; then
            echo "Client has been already exist."
        else
            echo "Add new client ${_mac_} ."
            $CMD -t $t -A $CHAIN -m mac --mac-source $_mac_ -j ACCEPT
        fi
    done
}

del ()
{
    local _mac_=$1
    for t in filter nat; do
        while [ true ]; do
            $CMD -t $t -S $CHAIN | grep -i $_mac_ > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "Delete client $_mac_ ."
                $CMD -t $t -D $CHAIN -m mac --mac-source $_mac_ -j ACCEPT
            else
                break
            fi
        done
    done
}

show ()
{
    for t in filter nat; do
        $CMD -t $t -S $CHAIN
    done
}

