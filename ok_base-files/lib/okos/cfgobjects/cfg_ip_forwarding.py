#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_tools import logcfg, logchecker
from constant import const

class CfgIpForwarding(CfgObj):
    differ = 'id'
    def __init__(self, entry=None):
        super(CfgIpForwarding, self).__init__()
        if entry:
            self.data.update(entry)
            self.data['id'] += '_ip'
    
    @classmethod
    @logcfg
    def parse(cls, j):
        ip_fwds = j['network'].setdefault('ip_forwardings',[])
        with ConfigParseEnv(ip_fwds, 'Port Forwarding configuration', debug=True):
            res = [cls(p) for p in ip_fwds]
        return res

    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'IP Forwarding configuration'):
            checker['id'] = (None, None)
            checker['interface_name'] = (None, None)
            checker['external_ip'] = (self._check_ipaddr_, None)
            checker['local_ip'] = (self._check_ipaddr_, None)

        cmd = ['set_port_forwarding.sh', 'set', checker['id'], '-S']
        cmd += ['--src-zone', 'UNTRUSTED', '--dst-zone', 'TRUSTED', ]
        cmd += ['--src-dip', checker['external_ip'], '--dst-ip', checker['local_ip'], '--proto', 'all', ]
        res = self.doit(cmd, 'Port Forwarding Setting')                
        return res
    @logcfg
    def remove(self):
        old = self.data
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'Port Forwarding removement'):
            checker['id'] = (self._check_entry_id_, None)
        cmd = ['set_port_forwarding.sh', 'del', checker['id'], '-S']
        res = self.doit(cmd, 'Port Forwarding Entry Removed')                
        return res
    @logcfg
    def change(self):
        self.add()
        return True

    @classmethod
    @logcfg
    def post_run(cls, cargo=None, goods=None):
        cls.add_service('firewall', cargo)
        return True