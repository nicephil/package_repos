#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgRadius(CfgObj):
    def __init__(self):
        super(CfgRadius, self).__init__('scheme')
    def parse(self, j):
        radiuss = j['server']['radiuss']
        res = [CfgRadius() for i in range(0, len(radiuss))]
        for i,r in enumerate(res):
            d = r.data
            rds = radiuss[i]
            d['scheme'] = rds['scheme']
            d['pri_auth_ip'] = rds['pri_auth_ip']
            d['pri_auth_port'] = rds['pri_auth_port']
            d['pri_auth_key_crypt'] = rds['pri_auth_key_crypt']
            d['pri_auth_key'] = rds['pri_auth_key']
        return res

