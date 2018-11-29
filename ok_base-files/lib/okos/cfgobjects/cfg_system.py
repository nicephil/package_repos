#!/usr/bin/env python

from cfg_object import CfgObj, ConfigParseEnv, ParameterChecker, ConfigInputEnv
from okos_tools import logcfg, log_err, UciSection, ExecEnv

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
        system = j['mgmt'].setdefault('system', {})
        with ConfigParseEnv(system, 'System configuration', debug=True):
            res = [cls(system),]            
        return res

    def _check_domain_id_(self, input):
        return True, str(input)

    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'System config input', debug=True):
            checker['domain_id'] = (self._check_domain_id_, '')
        if not checker['domain_id']:
            return True
        with ExecEnv('System', desc='setting', debug=True):
            system = UciSection('system', 'system')
            mac = UciSection('productinfo', 'productinfo')['serial']
            hostname = '{}_{}'.format(mac, checker['domain_id'])
            if hostname != system['domain_id']:
                system['domain_id'] = checker['domain_id']
                system['hostname'] = hostname
                system.commit()
        return True

    @logcfg
    def remove(self):
        return True

    @logcfg
    def change(self):
        self.remove()
        self.add()
        return True

    @classmethod
    @logcfg
    def post_run(cls, cargo=None, goods=None):
        cls.add_service('system', cargo)
        return True