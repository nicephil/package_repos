#!/usr/bin/env python

import argparse, os, subprocess, re, json
from cfg_object import CfgObj
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit

class CfgSystem(CfgObj):
    def __init__(self):
        super(CfgSystem, self).__init__('hostname')

    def parse(self, j):
        res = CfgSystem()
        d = res.data
        system = j['mgmt']['system']
        d['hostname'] = system['hostname']
        return [res,]

    def add(self):
        '''
        cmd = "hostname {hostname}".format(hostname=self.data['hostname'])
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False
        '''
        log_debug("add")
        return True

    def remove(self):
        log_debug("remove")
        return True;

    def change(self):
        log_debug("change")
        return True

