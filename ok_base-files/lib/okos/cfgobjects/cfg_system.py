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
        d['domain_id'] = system['domain_id'] if 'domain_id' in system else ''
        return [res,]

    def add(self):
        if not self.data['hostname'] or not self.data['domain_id']:
            return True

        signa = {
            'config':'system',
            'type':'system',
            'values':{
                'hostname':'{}_{}'.format(self.data['hostname'], self.data['domain_id'])
            }
        }
        try:
            ubus.call('uci','set', signa)
        except Exception, e:
            log_err("ubus uci gets failed, {}".format(e))
            return False
        cmd = "hostname {}_{}".format(self.data['hostname'], self.data['domain_id'])
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False

    def remove(self):
        return True

    def change(self):
        self.remove()
        self.add()
        return True
