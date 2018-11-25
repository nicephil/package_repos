#!/usr/bin/env python

import subprocess
from cfg_object import CfgObj, ConfigParseEnv
from okos_tools import log_debug, log_info, log_warning, log_err, log_crit, logcfg
import ubus

class CfgSystem(CfgObj):
    differ = 'hostname'

    def __init__(self, entry=None):
        super(CfgSystem, self).__init__()
        if entry:
            d = self.data
            d['hostname'] = entry.setdefault('hostname', '')
            d['domain_id'] = entry.setdefault('domain_id', '')

    @classmethod
    @logcfg
    def parse(cls, j):
        system = j['mgmt']['system']
        with ConfigParseEnv(system, 'System configuration', debug=True):
            res = [cls(system),]            
        return res

    @logcfg
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

    @logcfg
    def remove(self):
        return True

    @logcfg
    def change(self):
        self.remove()
        self.add()
        return True
