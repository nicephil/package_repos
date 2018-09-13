#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

###############################################################################
class CfgATFMode(CfgObj):
    def __init__(self):
        super(CfgATFMode, self).__init__()

    def parse(self, j):
        res = [CfgATFMode(), ]
        d = res[0].data
        d['atf_mode'] = j['wlan']['atf_mode'] if 'atf_mode' in j['wlan'] else 1
        return res

    def change(self):
        cmd = 'uci set wireless.qcawifi.atf_mode="' + str(self.data['atf_mode']) + '";' + \
            'uci commit wireless;' + 'wifi unload;wifi load'
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False
