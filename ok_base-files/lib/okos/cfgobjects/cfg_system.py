#!/usr/bin/env python

import argparse, os, subprocess, re, json
from cfg_object import CfgObj
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit
import ubus

class CfgSystem(CfgObj):
    def __init__(self):
        super(CfgSystem, self).__init__('hostname')

    def parse(self, j):
        res = CfgSystem()
        d = res.data
        system = j['mgmt']['system']
        d['hostname'] = system['hostname'] if 'hostname' in system else ''
        return [res,]

    def add(self):
        log_debug("add")

        if not self.data['hostname']:
            return True

        signa = {
            'config':'system',
            'type':'system',
            'values':{
                'hostname':self.data['hostname']
            }
        }
        try:
            ubus.call('uci','set', signa)
        except Exception, e:
            log_err("ubus uci gets failed, {}".format(e))
            return False
        cmd = "hostname {}".format(self.data['hostname'])
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False

    def remove(self):
        log_debug("remove")
        return True

    def change(self):
        log_debug("change")
        self.remove()
        self.add()
        return True
