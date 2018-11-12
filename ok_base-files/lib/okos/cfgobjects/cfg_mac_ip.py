#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_tools import logcfg, logchecker
from constant import const

class CfgMacIpBinding(CfgObj):
    def __init__(self, entry={}):
        super(CfgMacIpBinding, self).__init__(differ='id')
        self.data.update(entry)
    @logcfg
    def parse(self, j):
        mac_ips = j['network'].setdefault('mac_ips',[])
        with ConfigParseEnv(mac_ips, 'MAC IP binding configuration'):
            res = [CfgMacIpBinding(p) for p in mac_ips]
        return res

    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'MAC IP binding configuration'):
            checker['id'] = (self._check_simple_id_, None)
            checker['mac'] = (self._check_mac_, None)
            checker['ip'] = (self._check_ipaddr_, None)
            checker['name'] = (None, '')
        cmd = ['set_mac_ip.sh', 'set', checker['id'], '-S']
        cmd += ['--mac', checker['mac'], '--ip', checker['ip'], ]
        cmd += checker['name'] and ['--name', checker['name'], ] or []
        res = self.doit(cmd, 'MAC IP Binding')                
        return res
    @logcfg
    def remove(self):
        old = self.data
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'MAC IP binding remove'):
            checker['id'] = (self._check_simple_id_, None)
        cmd = ['set_mac_ip.sh', 'del', checker['id'],  '-S']
        res = self.doit(cmd, 'MAC IP binding Entry Removed')                
        return res
    @logcfg
    def change(self):
        self.add()
        return True

