#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgSystem(CfgObj):
    def __init__(self):
        super(CfgSystem, self).__init__()
    def parse(self, j):
        res = CfgSystem()
        d = res.data
        system = j['mgmt']['system']
        d['hostname'] = system['hostname']
        d['zone'] = system['zone']
        d['location'] = system['location']
        d['country_code'] = system['country_code']
        d['domain_name'] = system['domain_name']
        d['auth_url'] = system['auth_url']
        return [res,]
    def change(self):
        cmd = 'uci set system.@system[0].hostname="' + str(self.data['hostname']) + '";' + \
            'uci set system.@system[0].location="' + str(self.data['location']) + '";' + \
            'uci commit system;' + \
            'echo "' + str(self.data['hostname']) + '" > /proc/sys/kernel/hostname;'
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False

