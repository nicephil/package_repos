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

