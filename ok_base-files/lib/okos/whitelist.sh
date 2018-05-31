#!/bin/sh

CMD="iptables"
CHAIN_CC="ClientControl"
CHAIN_WL="WhiteList"
CHAIN_TP="GotoPortal"
CHAINS="$CHAIN_CC $CHAIN_WL $CHAIN_TP"
WHITELIST_TABLE="filter"
GOTOPORTAL_TABLE="nat"
LOGGER="logger -p 7 -t 'clientcontrol'"
#LOGGER="logger -t 'clientcontrol'"

add_to_whitelist ()
{
    local _mac_=$1
    [ -z "$_mac_" ] && echo "No MAC for adding to WhiteList" | $LOGGER
    for t in $WHITELIST_TABLE; do
        $CMD -t $t -S $CHAIN_WL | grep -i $_mac_
        if [ $? -eq 0 ]; then
            echo "Client has been already in WhiteList on table $t ." | $LOGGER
        else
            echo "Add new client $_mac_ to WhiteList on table $t ." | $LOGGER
            $CMD -t $t -A $CHAIN_WL -m mac --mac-source $_mac_ -j ACCEPT
        fi
    done
}

add_to_gotoportal ()
{
    local _mac_=$1
    [ -z "$_mac_" ] && echo "No MAC for adding to GotoPortal" | $LOGGER && return 1
    for t in $GOTOPORTAL_TABLE; do
        $CMD -t $t -S $CHAIN_TP | grep -i $_mac_
        if [ $? -eq 0 ]; then
            echo "Client has been already directed to GotoPortal on table $t ." | $LOGGER
        else
            echo "Add new client $_mac_ to GotoPortal on table $t ." | $LOGGER
            $CMD -t $t -A $CHAIN_TP -m mac --mac-source $_mac_ -j Portal
        fi
    done
}

del_from_whitelist ()
{
    local _mac_=$1
    [ -z "$_mac_" ] && echo "No MAC for deleting from WhiteList" | $LOGGER && return 1
    for t in $WHITELIST_TABLE; do
        for _i in 1 2 3; do
            $CMD -t $t -S $CHAIN_WL | grep -i $_mac_ > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "Delete client $_mac_ for WhiteList on table $t ." | $LOGGER
                $CMD -t $t -D $CHAIN_WL -m mac --mac-source $_mac_ -j ACCEPT
            else
                echo "client $_mac_ doesn't exist in WhiteList." | $LOGGER
                break
            fi
        done
    done
}

del_from_gotoportal ()
{
    local _mac_=$1
    [ -z "$_mac_" ] && echo "No MAC for deleting from GotoPortal" | $LOGGER && return 1
    for t in $GOTOPORTAL_TABLE; do
        for _i in 1 2 3; do
            $CMD -t $t -S $CHAIN_TP | grep -i $_mac_ > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "Delete client $_mac_ from GotoPortal on table $t ." | $LOGGER
                $CMD -t $t -D $CHAIN_TP -m mac --mac-source $_mac_ -j Portal
            else
                echo "client $_mac_ doesn't exist in GotoPortal." | $LOGGER
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

