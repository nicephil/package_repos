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
        cmd = "uci show wireless | awk -F'.' '/'\\\''%s'\\\''/{print $2;exit}'" % self.data['ssid']
        s = Popen(cmd, shell=True, stdout=PIPE)
        aths = s.communicate()[0]

        for ath in aths.split('\n'):
            print ath
            if len(ath) == 5:
                # 1. set enabled/disabled in configure
                cmd = "uci set wireless.%s.disabled=%d;uci commit wireless" % (ath, 0 if self.data['enabled'] else 1)
                s = Popen(cmd, shell=True, stdout=PIPE)
                result = s.communicate()[0]
                print result
                if len(result) != 0:
                    ret = False
                # 2. up/down the related VAP
                cmd = "ifconfig %s %s" % (ath, "up" if self.data['enabled'] else "down")
                s = Popen(cmd, shell=True, stdout=PIPE)
                result = s.communicate()[0]
                print result
                if len(result) != 0:
                    ret = False

        return ret

