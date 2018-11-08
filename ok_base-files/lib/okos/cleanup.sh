disable_capwapc()
{
    /etc/init.d/supervisor stop
    /etc/init.d/capwapc stop
}

disable_clientevent()
{
    /etc/init.d/supervisor stop
    killall -9 clientevent.py
    killall -9 tcpdump
    sed -i '1 iexit' /lib/okos/wifievent.sh
    for chain in INPUT FORWARD OUTPUT
    do
        iptables -P $chain ACCEPT
        iptables -F $chain
    done
    for chain in PREROUTING INPUT POSTROUTING OUTPUT
    do
        iptables -t nat -P $chain ACCEPT
        iptables -t nat -F $chain
    done
    for chain in PREROUTING INPUT FORWARD POSTROUTING OUTPUT
    do
        iptables -t mangle -P $chain ACCEPT
        iptables -t mangle -F $chain
    done

    # 8. ebtables cleanup
    for chain in INPUT FORWARD OUTPUT
    do
        ebtables -P $chain ACCEPT
        ebtables -F $chain
    done
}

disable_kernel()
{
    sysctl -w net.core.netdev_max_backlog=10000
    sysctl -w net.core.netdev_budget=3000
}


disable_arpwatch()
{
    /etc/init.d/supervisor stop
    killall -9 clientevent.py
    killall -9 tcpdump
    sed -i -e '/^.*arpwatch.*$/d' -e '/^.*agent.*$/d' /lib/okos/clientevent.py
}


disable_crontab()
{
    /etc/init.d/supervisor stop
    killall -9 runtimefixup.sh
    killall -9 apstats.sh
    killall -9 setgre.sh
    /etc/init.d/cron stop
}

disable_predownload()
{
    /etc/init.d/supervisor stop
    killall -9 wget
    killall -9 S99predownload
    /etc/init.d/predownload stop
}

disable_syslog()
{
    /etc/init.d/boot stop
}

echo "usage:"
echo "capwapc=1 clientevent=1 crontab=1 predownload=1 syslog=1 kernel=1 sh /lib/okos/cleanup.sh"
echo ""

echo "======current env========="
export
echo "======end========="

[ -n "$capwapc" ] && {
    disable_capwapc
}

[ -n "$clientevent" ] && {
    disable_clientevent
}

[ -n "$crontab" ] && {
    disable_crontab
}

[ -n "$predownload" ] && {
    disable_predownload
}

[ -n "$arpwatch" ] && {
    disable_arpwatch
}

[ -n "$syslog" ] && {
    disable_syslog
}

[ -n "$kernel" ] && {
    disable_kernel
}
