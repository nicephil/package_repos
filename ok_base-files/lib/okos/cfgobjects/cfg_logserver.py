#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgLogServer(CfgObj):
    def __init__(self):
        super(CfgLogServer, self).__init__()
    def parse(self, j):
        res = [CfgLogServer(),]
        d = res[0].data
        log = j['server']['log']
        d['enabled'] = bool(log['enabled'])
        d['server'] = log['server']
        d['level'] = log['log_server_level']
        return res
    def change(self):
        pass

