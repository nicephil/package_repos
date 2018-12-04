#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_tools import logcfg, logchecker
from constant import const

class CfgDhcpOption(CfgObj):
    differ = 'id'
    def __init__(self, entry=None, dhcp_pool=None):
        super(CfgDhcpOption, self).__init__()
        if entry and dhcp_pool:
            self.data.update(entry)
            self.data['pool'] = dhcp_pool['ifname']
            #self.data['option_id'] = '%s_%s' % (self.data['pool'], self.data['id'])

    @classmethod
    @logcfg
    def parse(cls, j):
        dhcp_options = j['network'].setdefault('dhcp_options',[])
        dhcp_pools = j['network'].setdefault('local_networks', [])
        with ConfigParseEnv(dhcp_pools, 'DHCP Options configuration', debug=True):
            res = [cls(o,p) for o in dhcp_options for p in dhcp_pools if p['dhcp_server_enable'] for oid in p['dhcp_option_ids'] if oid == o['id']]
        return res
    
    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'DHCP Option configuration'):
            checker['id'] = (None, None)
            checker['option'] = (None, None)
            checker['value'] = (None, None)
            checker['pool'] = (None, None)

        cmd = ['set_dhcp_option.sh', 'set', '-S']
        cmd += ['--option', checker['option'], '--value', checker['value'], '--pool', checker['pool']]
        res = self.doit(cmd, 'DHCP Option Setting')                
        return res

    @logcfg
    def remove(self):
        old = self.data
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'DHCP Option removement'):
            checker['id'] = (None, None)
            checker['option'] = (None, None)
            checker['value'] = (None, None)
            checker['pool'] = (None, None)

        cmd = ['set_dhcp_option.sh', 'del', '-S']
        cmd += ['--option', checker['option'], '--value', checker['value'], '--pool', checker['pool']]
        res = self.doit(cmd, 'DHCP Option Entry Removed')                
        return res

    @logcfg
    def change(self):
        self.add()
        return True

    @classmethod
    @logcfg
    def post_run(cls, cargo=None, goods=None):
        cls.add_service('dnsmasq', cargo)
        return True