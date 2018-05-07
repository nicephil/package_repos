import argparse, os, re, json, pprint
from cfg_object import CfgObj
from subprocess import Popen, PIPE

class CfgSsidEnabled(CfgObj):
    def __init__(self):
        super(CfgSsidEnabled, self).__init__('ssid')
    def parse(self, j):
        ssids = j['wlan']['ssids']
        res = [CfgSsidEnabled() for s in ssids]
        for i,r in enumerate(res):
            d = r.data
            ssids[i]['__template_id'] = i
            d['ssid'] = ssids[i]['ssid']
            d['enabled'] = 1 if not 'enabled' in ssids[i].keys() else ssids[i]['enabled']
        return res
    def change(self):
        ret = True
        # 0. find the VAP and config
        cmd = "uci show wireless | awk -F'.' '/'\\\''%s'\\\''/{print $2}'" % self.data['ssid']
        s = Popen(cmd, shell=True, stdout=PIPE)
        aths = s.communicate()[0]

        for ath in aths.split('\n'):
            print ath, self.data['ssid'], self.data['enabled']
            if len(ath) == 5:
                # 1. up/down the related VAP
                cmd = "ifconfig %s %s 2>&1" % (ath, "up" if self.data['enabled'] else "down")
                s = Popen(cmd, shell=True, stdout=PIPE)
                result = s.communicate()[0]
                if len(result) != 0:
                    print "bbb", ath, self.data['enabled'], result
                    ret = False
                    return ret
                # 2. set enabled/disabled in configure
                cmd = "uci set wireless.%s.disabled=%d;uci commit wireless;uci set wlan_service_template.ServiceTemplate%s.service_template=%s;uci commit wlan_service_template;" % \
                    (ath, 0 if self.data['enabled'] else 1, ath[4:], "enabled" if self.data['enabled'] else "disabled")
                s = Popen(cmd, shell=True, stdout=PIPE)
                result = s.communicate()[0]
                if len(result) != 0:
                    print "ddd", ath, self.data['enabled'], result
                    ret = False
                    return ret

        return ret

