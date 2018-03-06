#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj

class CfgCapwap(CfgObj):
    def __init__(self):
        super(CfgCapwap, self).__init__()
    def parse(self, j):
        res = CfgCapwap()
        d = res.data
        capwap = j['server']['capwap']
        d['enabled'] = bool(capwap['enabled'])
        d['master'] = capwap['master_server']
        d['mtu'] = capwap['mtu']
        d['control_port'] = capwap['control_port']
        d['echo_interval'] = capwap['echo_interval']
        return [res,]

