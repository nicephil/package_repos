#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgPortal(CfgObj):
    def __init__(self):
        super(CfgPortal, self).__init__('scheme')
    def parse(self, j):
        portals = j['wlan']['portal_schemes']
        res = [CfgPortal() for i in range(0, len(portals))]
        for i,r in enumerate(res):
            d = r.data
            p = portals[i]
            d['scheme'] = p['scheme']
            d['enabled'] = bool(p['enable'])
            d['url'] = p['url']
            d['auth_server'] = p['auth_ip']
            d['whitelist_ip'] = p['whitelist_ip']
            d['domain_set_name'] = p['domain_set_name']
        return res

