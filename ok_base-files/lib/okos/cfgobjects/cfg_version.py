#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

###############################################################################
class CfgVersion(CfgObj):
    def __init__(self):
        super(CfgVersion, self).__init__()
    def parse(self, j):
        res = [CfgVersion(), ]
        d = res[0].data
        d['version'] = j['config_version']
        return res
    def change(self):
        cmd = 'uci set okcfg.config.version="' + str(self.data['version']) + '";' + \
            'uci commit okcfg;'
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False
