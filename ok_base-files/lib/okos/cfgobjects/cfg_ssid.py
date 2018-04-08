#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgSsid(CfgObj):
    def __init__(self):
        super(CfgSsid, self).__init__('ssid')
    def parse(self, j):
        ssids = j['wlan']['ssids']
        res = [CfgSsid() for s in ssids]
        for i,r in enumerate(res):
            d = r.data
            ssids[i]['__template_id'] = i
            d['ssid'] = ssids[i]['ssid']
            d['type'] = ssids[i]['type']
            d['beacon_ssid_hide'] = ssids[i]['ssid_hide']
            d['client_max'] = ssids[i]['client_max']
            d['ptk_lifetime'] = ssids[i]['ptk_lifetime']
            d['ptk_enabled'] = ssids[i]['ptk_enabled']
            d['gtk_lifetime'] = ssids[i]['gtk_lifetime']
            d['gtk_enabled'] = ssids[i]['gtk_enabled']
            d['bandwidth_priority'] = ssids[i]['bandwidth_priority']
            d['client_isolation'] = ssids[i]['client_isolation']
            d['psk_key'] = ssids[i].setdefault('key', '')
            d['portal_scheme'] = ssids[i]['portal_scheme']
            d['auth'] = ssids[i]['auth']
            d['uplink_limit_enable'] = ssids[i]['uplink_limit_enable']
            d['downlink_limit_enable'] = ssids[i]['downlink_limit_enable']
            d['bandwidth_priority'] = ssids[i]['bandwidth_priority']
            d['radios'] = [p['radio'] for p in j['ports'] if p['name'] == d['ssid']]
            d['vlan'] = {p['pvlan'] for p in j['ports'] if p['name'] == d['ssid']}
        return res

