#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

###############################################################################
class CfgDomainNameSet(CfgObj):
    def __init__(self):
        super(CfgDomainNameSet, self).__init__('name')
    def parse(self, j):
        dns = j['wlan']['domain_sets']
        res = [CfgDomainNameSet() for i in range(0, len(dns))]
        for i,r in enumerate(res):
            d = r.data
            dn = dns[i]
            d['name'] = dn['name']
            d['keys'] = dn['keys']
        return res
