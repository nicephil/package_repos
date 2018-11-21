#!/usr/bin/env python

from cfg_object import CfgObj, ConfigParseEnv, ParameterChecker, ConfigInputEnv
from okos_tools import *

class CfgDDNS(CfgObj):
    def __init__(self, entry=None):
        super(CfgDDNS, self).__init__(differ='id')
        entry and self.data.update(entry)

    @logcfg
    def parse(self, j):
        ddnss = j['network'].setdefault('ddnss',[])
        with ConfigParseEnv(ddnss, 'DDNS configuration'):
            res = [CfgDDNS(ddns) for ddns in ddnss]
        res = [CfgDDNS() for d in ddnss]

    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'DDNS config'):
            checker['id'] = (None, None)
            checker['interface_name'] = (None, None)
            checker['ip'] = (self._check_ipaddr_, None)
            checker['provider'] = (None, None)
            checker['hostname'] = (None, None)
            checker['username'] = (None, None)
            checker['password'] = (None, None)
        cmd = ['set_ddns.sh', 'set', checker['id'], '-S']
        cmd += ['--provider', checker['provider'], '--hostname', checker['hostname'],
                '--username', checker['username'], '--password', checker['password'],
                '--interface_name', checker['interface_name'], '--ipaddr', checker['ip'],
                ]
        res = self.doit(cmd, 'DDNS entry added')                
        return res

    @logcfg
    def change(self):
        self.add()
        return True

    @logcfg
    def remove(self):
        old = self.data
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'DDNS entry remove'):
            checker['id'] = (None, None)
        cmd = ['set_ddns.sh', 'del', checker['id'], '-S']
        res = self.doit(cmd, 'DDNS Entry Removed')                
        return res

    @logcfg
    def post_run(self):
        self.doit(['/etc/init.d/ddns', 'reload'], 'Restart ddns', path='')
        return True


