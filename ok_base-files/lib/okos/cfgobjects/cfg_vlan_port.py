#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgVlanPort(CfgObj):
    def __init__(self):
        super(CfgVlanPort, self).__init__()
    def parse(self, j):
        vlan_ports = j['ports']
        res = [CfgVlanPort() for i in range(0, len(vlan_ports))]
        for i,r in enumerate(res):
            d = r.data
            p = vlan_ports[i]
            d['name'] = p['name']
            d['radio'] = p['radio']
            d['type'] = p['type']
            d['pvlan'] = p['pvlan']
        return res

