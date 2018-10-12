#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv
from okos_utils import logcfg
#import ubus
from constant import const

class CfgNetwork(CfgObj):
    def __init__(self):
        super(CfgNetwork, self).__init__()
    
    def _consume(self, vlan, ifs):
        self.data.update(vlan)
        for ifname,ifx in ifs.iteritems():
            native_vlan = ifx.setdefault('native_vlan', 1)
            if vlan['id'] in ifx['local_network_ids']:
                self.data['ifname'] = ifname
                self.data['untagged'] = bool(native_vlan == vlan['vlan'])
        return self

    @logcfg
    def parse(self, j):
        vlans = j['network'].setdefault('local_networks',[])
        with ConfigParseEnv(vlans, 'VLAN configuration'):
            res = [CfgNetwork()._consume(vlan, j['interfaces']) for vlan in vlans]

        self.log_debug('config data: %s' % (self.data))
        return res

    @logcfg
    def add(self):
        new = self.data
        with ConfigInputEnv(new, 'VLAN configuration'):
            if 'ifname' not in new:
                self.log_warning('VLAN %s is not bound to any interface' % (new['id']))
                return True
            else:
                ipaddr, netmask, vid, untagged = new['gateway'], new['netmask'], new['vlan'], new['untagged']
                dhcp_server_enabled = new.setdefault('dhcp_server_enable', 0)
                dhcp_pool = dhcp_server_enabled and {
                    'start': str(new['dhcp_start']),
                    'limit': str(new['dhcp_limit']),
                    'leasetime': str(new['dhcp_lease_time']),} or {}
                ifname = const.PORT_MAPPING_LOGIC[new['ifname']]['ifname']
            if untagged:
                cmd = [const.CONFIG_BIN_DIR+'set_lan_ip.sh', ifname, ipaddr, netmask]
                self.doit(cmd, 'Change IP address of LAN port')
        return True

    @logcfg
    def remove(self):
        return True

    @logcfg
    def change(self):
        return True

