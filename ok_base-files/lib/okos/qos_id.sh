qos_id_log ()
{
    local pri=$1
    shift 1
    echo "$@" | logger -t qos_id -p 3
}

qos_id_trap ()
{
    qos_id_log $LOG_DEBUG "QoS Trapped."
    lock -u /var/run/qos.lock
}
trap 'qos_id_trap; exit' INT TERM ABRT QUIT ALRM



id_file="/tmp/qos_client_id"
#id_base=0x100
id_base=256
mask_id=0xFF
#split_id=0x7F00
split_id=32512

#####################################################
# also used by ebtables in clienttrack to mark packets
# 0x0 - 0xFF used by wifidog
# 0x01xx - 0x7Fxx used by qos uplink
# 0x80xx - 0xFFxx used by qos donwlink
# Format of ID file: /tmp/qos_client_id
# -------------------------------------------------
# MAC                Interface   ID   ID_HEX
# fc:ad:0f:06:a3:28  ath11       256  100
# f0:b4:29:c7:70:da  ath01       512  200
# f4:0f:24:2d:da:08  ath10       768  300
#
#####################################################

qos_get_id ()
{
    [ ! -f $id_file ] && qos_id_log $LOG_DEBUG "$id_file is absent, create new one." &&  touch $id_file
    qos_id_log $LOG_DEBUG "get_id(): for $mac ."

    local mac=$1

    lock /var/run/qos.lock
    local ck=`grep -i "${mac}" ${id_file}`
    lock -u /var/run/qos.lock
    qos_id_log $LOG_DEBUG "get_id(): $ck ."

    # Reture entry corresponding to given MAC.
    echo "${ck}"
}

qos_new_id ()
{
    local mac=`echo $1 | tr 'A-Z' 'a-z'`
    local ifname=$2
    qos_id_log $LOG_DEBUG "new_id(): (MAC:$mac , IFNAME:$ifname)"

    lock /var/run/qos.lock
    local id=$id_base
    local ids=`cat $id_file | awk '{print $3}'`
    for n in $ids; do
        for m in $ids; do
            if [ $id -eq $m ]; then
                id=$(( id + $id_base ))
                break
            fi
        done
    done

    echo "$mac $ifname $id $(printf "%04x" $id)" >> $id_file
    lock -u /var/run/qos.lock
    qos_id_log $LOG_DEBUG "new_id(): get ID:$id ."
    echo "$id"
}

qos_del_id ()
{
    local id=$1
    qos_id_log $LOG_DEBUG "del_id(): ID:$id "
    lock /var/run/qos.lock
    sed -i "/ ${id}$/d" ${id_file}
    lock -u /var/run/qos.lock

    qos_id_log $LOG_DEBUG "del_id(): done."
}


qos_del_id_by_mac ()
{
    local mac=$1
    qos_id_log $LOG_DEBUG "del_id_by_mac(): MAC:$mac "
    lock /var/run/qos.lock
    sed -i "/^${mac} /d" ${id_file}
    lock -u /var/run/qos.lock

    qos_id_log $LOG_DEBUG "del_id_by_mac(): done."
}

qos_del_all_ids ()
{
    qos_id_log $LOG_DEBUG "del_all_ids()"
    lock /var/run/qos.lock
    echo "" >  ${id_file}
    lock -u /var/run/qos.lock

    qos_id_log $LOG_DEBUG "del_all_ids(): done."
}

