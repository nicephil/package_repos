#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgNetwork(CfgObj):
    def __init__(self):
        super(CfgNetwork, self).__init__('vlanid')
    def parse(self, j):
        ports = j['ports']
        ssids = j['wlan']['ssids']
        vlans = list({p['pvlan'] for p in ports if p['radio'] >= 0})
        res = [CfgNetwork() for v in vlans]
        for i,r in enumerate(res):
            d = r.data
            d['vlanid'] = vlans[i]
            d['ports'] = ['ath'+str(p['radio'])+str(s['__template_id'])
                for p in ports if p['radio'] >= 0 if p['pvlan'] == vlans[i]
                for s in ssids if s['ssid'] == p['name']]
        return res

