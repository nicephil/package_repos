#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ParameterChecker
from okos_utils import logcfg, logchecker
#import ubus
from constant import const

class CfgNetwork(CfgObj):
    def __init__(self, vlan={}, ifx={}, ifname=''):
        super(CfgNetwork, self).__init__(differ='vlan')
        d = self.data
        d.update(vlan)
        if vlan and ifx and ifname:
            d['ifname'] = const.PORT_MAPPING_LOGIC[ifname]['ifname']
            d['untagged'] = bool(ifx.setdefault('native_vlan', 1) == d.setdefault('vlan',1))
            vlan['ifname'] = d['untagged'] and d['ifname'] or '{}_{}'.format(d['ifname'], d['vlan'])

    @logcfg
    def parse(self, j):
        vlans = j['network'].setdefault('local_networks',[])
        ifs = j.setdefault('interfaces', [])
        with ConfigParseEnv(vlans, 'VLAN configuration'):
            res = [CfgNetwork(vlan, ifx, ifname) for vlan in vlans
                                            for ifname, ifx in ifs.iteritems()
                                                if ifx['type'] == const.DEV_CONF_PORT_TYPE['lan']
                                                    if vlan['id'] in ifx['local_network_ids'] ]
        return res
    
    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'VLAN: %s config' % (new['vlan'])):
            checker = ParameterChecker(new)
            checker['ifname'] = (None, None)
            checker['gateway'] = (self._check_ipaddr_, None)
            checker['netmask'] = (self._check_ipaddr_, None)
            checker['vlan'] = (None, None)
            checker['untagged'] = (None, None)
            checker['security_zone'] = (self._check_zone_, None)
            checker['dhcp_server_enable'] = (None, 0)
            if checker['dhcp_server_enable']:
                checker['dhcp_start'] = (None, None)
                checker['dhcp_limit'] = (None, None)
                checker['dhcp_lease_time'] = (None, 38400)
        cmd = ['set_vlan.sh', checker['ifname'], '-S',]
        cmd += ['--ipaddr', checker['gateway'], '--netmask', checker['netmask'],]
        cmd_vlan = not checker['untagged'] and ['--vid', str(checker['vlan']),] or []
        cmd += cmd_vlan
        cmd += ['--zone', checker['security_zone']]
        res = self.doit(cmd, 'Change IP address of LAN interface')

        cmd = ['set_dhcp_server.sh', checker['ifname'], '-S', ]
        cmd += cmd_vlan
        cmd += checker['dhcp_server_enable'] and ['--start', checker['dhcp_start'], '--limit', checker['dhcp_limit'], '--lease', checker['dhcp_lease_time'],] or ['-R',]
        res &= self.doit(cmd, 'Set DHCP pool of vlan')
        return res

    @logcfg
    def remove(self):
        old = self.data
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'VLAN: %s remove' % (old['vlan'])):
            checker['ifname'] = (None, None)
            checker['vlan'] = (None, None)
            checker['untagged'] = (None, None)
            checker['security_zone'] = (self._check_zone_, None)
            checker['dhcp_server_enable'] = (None, 0)
            ifname = checker['ifname']
        res = True
        if not checker['untagged']:
            cmd = ['set_vlan.sh', ifname, '-S', '-R']
            cmd += ['--zone', checker['security_zone'],]
            cmd += ['--vid', checker['vlan'],]
            res &= self.doit(cmd, 'Disable VLAN interface')
        if checker['dhcp_server_enable']:
            cmd = ['set_dhcp_server.sh', ifname, '-S', '-R']
            cmd += not checker['untagged'] and ['--vid', checker['vlan'], ] or []
            res &= self.doit(cmd, "Disable DHCP Server")
        return res

    @logcfg
    def change(self):
        self.add()
        return True
