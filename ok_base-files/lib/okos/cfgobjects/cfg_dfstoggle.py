#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

###############################################################################
class CfgDFSToggle(CfgObj):
    def __init__(self):
        super(CfgDFSToggle, self).__init__()

    def parse(self, j):
        res = [CfgDFSToggle(), ]
        d = res[0].data
        d['dfs_toggle'] = j['wlan']['dfs_toggle'] if 'dfs_toggle' in j['wlan'] else 1
        return res

    def change(self):
        enable_str = "enable" if self.data['dfs_toggle'] else "disable"
        cmd = 'radartool -i wifi1 ' + enable_str + ';' +'uci set wireless.wifi0.dfs_toggle="' + str(self.data['dfs_toggle']) + '";' + \
            'uci set wireless.wifi1.dfs_toggle="' + str(self.data['dfs_toggle']) + '";' + \
            'uci commit wireless;'
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False
