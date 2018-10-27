#!/bin/sh

# 1. stop supervisor

/etc/init.d/supervisor stop

# 2. stop services
# 2.1 to nms connection
/etc/init.d/capwapc stop
# 2.2 portal related
/etc/init.d/wifidog stop
# 2.3 query to redirector
/etc/init.d/handle_cloud stop
# 2.4 iptables related
/etc/init.d/apfw.dyn stop
/etc/init.d/apfw.static stop
# 2.5 tc related
/etc/init.d/qos stop
# 2.6 predownload image related
/etc/init.d/predownload stop
# 2.7 system status monitor related
/etc/init.d/sysstat stop
# 2.8 ntp related
/etc/init.d/sysntpd stop
# 2.9 schedule related
/etc/init.d/atd stop
/etc/init.d/cron stop
# 3.0 stop wifi
wifi down

# 3. clean wifi config
# 3.0 fetch the default wifi config
[ -f /etc/defcfg/wireless ] && cp  /etc/defcfg/wireless /etc/config/wireless
# 3.1 set channel
uci set wireless.wifi1.channel='44'       ########## channel setting
# 3.2 set txpower
uci set wireless.wifi1.txpower='21'       ########### txpower setting
# 3.3 set htmode
uci set wireless.wifi1.htmode='HT20'      ########## htmode setting
# 3.4 enable wifi1 based on default wifi config
uci set wireless.wifi1.disabled='0'

# 3.4 set ssid based on default wifi config
uci set wireless.ath60.ssid='ok_5g'        ######## ssid setting
uci set wireless.ath60.network='lan1'
uci set wireless.ath60.encryption='open'
uci set wireless.ath60.hidden='0'

# 3.5 disable station log
uci set wireless.wifi1.enable_ol_stats='0'
# 3.6 disable airtime fairness
uci set wireless.wifi1.atf_mode='0'
# 3.7 disable dfs detection  
uci set wireless.wifi1.dfs_toggle='0'
uci commit wireless

# 4. apply the wireless config
wifi up

sleep 10

# 5. clear other default config by iwpriv directly
# 5.1 disable channel util measurement 
ifname="ath60"
iwpriv "$ifname" chutil_enab 0
# 5.2 disable status monitor
iwpriv "$ifname" txrx_vap_stats 0
iwpriv "$ifname" txrx_fw_stats 0
iwpriv "$ifname" txrx_fw_mstats 0
iwpriv "$ifname" rxdropstats 0
iwpriv "$ifname" atfssidgroup 0

# 6. kernel tunnable params
# 6.1 softirq backlog
sysctl -w net.core.netdev_max_backlog=10000
sysctl -w net.core.netdev_budget=3000

# 7. iptables cleanup
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

