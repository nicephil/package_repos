#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_utils import logcfg, logchecker
#import ubus
from constant import const

class CfgDhcpOption(CfgObj):
    def __init__(self, entry={}, dhcp_pool={}):
        super(CfgDhcpOption, self).__init__(differ='option_id')
        self.data.update(entry)
        if dhcp_pool:
            self.data['pool'] = dhcp_pool['ifname']
            self.data['option_id'] = '%s_%s' % (self.data['pool'], self.data['id'])

    @logcfg
    def parse(self, j):
        dhcp_options = j['network'].setdefault('dhcp_options',[])
        dhcp_pools = j['network'].setdefault('local_networks', [])
        with ConfigParseEnv(dhcp_pools, 'DHCP Options configuration'):
            res = [CfgDhcpOption(o,p) for o in dhcp_options for p in dhcp_pools if p['dhcp_server_enable'] for oid in p['dhcp_option_ids'] if oid == o['id']]
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

