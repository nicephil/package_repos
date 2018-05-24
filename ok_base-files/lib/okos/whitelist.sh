#!/bin/sh

CMD="iptables"
CHAIN_CC="ClientControl"
CHAIN_WL="WhiteList"
CHAIN_TP="GotoPortal"
CHAINS="$CHAIN_CC $CHAIN_WL $CHAIN_TP"

add_to_whitelist ()
{
    local _mac_=$1
    for t in filter nat; do
        $CMD -t $t -S $CHAIN_WL | grep -i $_mac_
        if [ $? -eq 0 ]; then
            echo "Client has been already in WhiteList on table $t ."
        else
            echo "Add new client $_mac_ to WhiteList on table $t ."
            $CMD -t $t -A $CHAIN_WL -m mac --mac-source $_mac_ -j ACCEPT
        fi
    done
}

add_to_gotoportal ()
{
    local _mac_=$1
    #for t in filter nat; do
    for t in nat; do
        $CMD -t $t -S $CHAIN_TP | grep -i $_mac_
        if [ $? -eq 0 ]; then
            echo "Client has been already directed to GotoPortal on table $t ."
        else
            echo "Add new client $_mac_ to GotoPortal on table $t ."
            $CMD -t $t -A $CHAIN_TP -m mac --mac-source $_mac_ -j Portal
        fi
    done
}

del_from_whitelist ()
{
    local _mac_=$1
    for t in filter nat; do
        while [ true ]; do
            $CMD -t $t -S $CHAIN_WL | grep -i $_mac_ > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "Delete client $_mac_ for WhiteList on table $t ."
                $CMD -t $t -D $CHAIN_WL -m mac --mac-source $_mac_ -j ACCEPT
            else
                break
            fi
        done
    done
}

del_from_gotoportal ()
{
    local _mac_=$1
    #for t in filter nat; do
    for t in nat; do
        while [ true ]; do
            $CMD -t $t -S $CHAIN_TP | grep -i $_mac_ > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "Delete client $_mac_ from GotoPortal on table $t ."
                $CMD -t $t -D $CHAIN_TP -m mac --mac-source $_mac_ -j Portal
            else
                break
            fi
        done
    done
}

show ()
{
    for t in filter nat; do
        for chain in $CHAINS; do
            $CMD -t $t -S $chain
        done
    done
}

