#!/usr/bin/env python

from cfg_object import CfgObj, ConfigParseEnv, ParameterChecker, ConfigInputEnv
from okos_tools import logcfg, log_err, UciSection

class CfgSystem(CfgObj):
    #differ = 'hostname'

    def __init__(self, entry=None):
        super(CfgSystem, self).__init__()
        if entry:
            d = self.data
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
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'System configuration', debug=True):
            checker['domain_id'] = (None, '')
        if not checker['domain_id']:
            return True
        system = UciSection('system', 'system')
        if checker['domain_id'] != system['domain_id']:
            system['domain_id'] = checker['domain_id'] 
            system.commit()
            hostname = '{}_{}'.format(system['hostname'], system['domain_id'])
            cmd = ['/bin/hostname', hostname]
            ret = self.doit(cmd, 'Set Hostname')
            return ret
        else:
            return True

    @logcfg
    def remove(self):
        return True

    @logcfg
    def change(self):
        self.remove()
        self.add()
        return True
