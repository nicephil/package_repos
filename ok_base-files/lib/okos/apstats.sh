#!/bin/sh

# 1. generate apstats log
apstats -a -R > /tmp/apstats.log

# 2. awk search 'Node Level Stats' and parse the 'Tx Data Bytes' 'Rx Data Bytes'
# 'Average Tx Rate (kbps)' 'Average Rx Rate (kbps)'
awk -F'[ =]+' '/Node Level Stats/{

node=$4;
vap=substr($7,1,length($7)-1);

while (getline > 0 && length($0) > 0) {
    if (match($1$2$3,"TxDataBytes")) {
        txB=$4;
    } else if (match($1$2$3,"RxDataBytes")) {
        rxB=$4
    } else if (match($1$2$3,"AverageTxRate")) {
        atxrb=$5
    } else if (match($1$2$3,"AverageRxRate")) {
        arxrb=$5
    } else if (match($1$2,"Txfailures")) {
        txfs=$3
    } else if (match($1$2,"Rxerrors")) {
        rxes=$3
    }
}

print node,vap,txB,rxB,atxrb,arxrb,txfs,rxes


}' /tmp/apstats.log



exit
