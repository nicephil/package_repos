#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgNtp(CfgObj):
    def __init__(self):
        super(CfgNtp, self).__init__()
    def parse(self, j):
        res = CfgNtp()
        d = res.data
        ntp = j['server']['ntp']
        d['enabled'] = bool(ntp['enabled'])
        d['period'] = ntp['period']
        d['servers'] = ntp['servers']
        return [res,]


