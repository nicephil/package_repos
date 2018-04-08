#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgRadio(CfgObj):
    def __init__(self):
        super(CfgRadio, self).__init__('id')
    def parse(self, j):
        ifs = { c['name']: bool(c['enabled']) for c in j['interfaces'] if c['name'].find('wifi') >= 0}
        radios = j['wlan']['radios']
        system = j['mgmt']['system']
        res = [CfgRadio() for r in radios]
        for i,r in enumerate(res):
            d = r.data
            radio = radios[i]
            d['id'] = radio['id']
            d['enabled'] = ifs['wifi'+str(d['id'])]
            d['hwmode'] = radio['mode']
            d['channel'] = radio['channel']
            d['bandwidth'] = radio['bandwidth']
            d['txpower'] = radio['max_power']
            d['rssi_access'] = radio['rssi_access']
            d['rssi_access_threshold'] = radio['rssi_access_threshold']
            d['client_max'] = radio['client_max']
            d['country_code'] = system['country_code']
        return res

