qos_id_log ()
{
    local pri=$1
    shift 1
    echo "$@" | logger -t qos_id -p 3
}

#####################################################
# MAC address (high 16 ^ middle 16 ^ lower 16) & 0xFFFE as fwmark id
#####################################################
#((split_id=1))
split_id=1

qos_get_id ()
{
    qos_id_log $LOG_DEBUG "get_id(): for $mac ."
    local mac=$1
    OIFS=$IFS;IFS=':';set -- $mac;mac_h=0x$1$2;mac_m=0x$3$4;mac_l=0x$5$6;IFS=$OIFS
    local ck=$(((mac_h ^ mac_m ^ mac_l)&0xFFFE))

    qos_id_log $LOG_DEBUG "get_id(): $ck ."

    # Reture entry corresponding to given MAC.
    echo ${ck}
}

qos_new_id ()
{
    local mac=$1
    qos_id_log $LOG_DEBUG "new_id(): (MAC:$mac , IFNAME:$ifname)"
    OIFS=$IFS;IFS=':';set -- $mac;mac_h=0x$1$2;mac_m=0x$3$4;mac_l=0x$5$6;IFS=$OIFS
    local id=$(((mac_h^mac_m^mac_l)&0xFFFE))
    qos_id_log $LOG_DEBUG "new_id(): get ID:$id ."
    echo ${id}
}

qos_del_id ()
{
    local id=$1
    qos_id_log $LOG_DEBUG "del_id(): ID:$id "
    qos_id_log $LOG_DEBUG "del_id(): done."
}


qos_del_id_by_mac ()
{
    local mac=$1
    qos_id_log $LOG_DEBUG "del_id_by_mac(): MAC:$mac "
    qos_id_log $LOG_DEBUG "del_id_by_mac(): done."
}

qos_del_all_ids ()
{
    qos_id_log $LOG_DEBUG "del_all_ids()"
    qos_id_log $LOG_DEBUG "del_all_ids(): done."
}

