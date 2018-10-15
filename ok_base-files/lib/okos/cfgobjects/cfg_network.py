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
            if ifx['type'] == const.DEV_CONF_PORT_TYPE['lan']:
                native_vlan = ifx.setdefault('native_vlan', 1)
                if vlan['id'] in ifx['local_network_ids']:
                    self.data['ifname'] = ifname
                    self.data['untagged'] = bool(native_vlan == vlan['vlan'])
        return self

    @logcfg
    def parse(self, j):
        vlans = j['network'].setdefault('local_networks',[])
        with ConfigParseEnv(vlans, 'VLAN configuration'):
            res = [CfgNetwork() for vlan in vlans]
            for i, vlan in enumerate(vlans):
                res[i]._consume(vlan, j['interfaces'])
        return res

    @logcfg
    def add(self):
        new = self.data
        with ConfigInputEnv(new, 'VLAN configuration'):
            if 'ifname' not in new:
                self.log_warning('VLAN %s is not bound to any interface' % (new['id']))
                return True
            else:
                ipaddr, netmask, vid, untagged, zone = new['gateway'], new['netmask'], new['vlan'], new['untagged'], new['security_zone']
                dhcp_server_enabled = new.setdefault('dhcp_server_enable', 0)
                dhcp_pool = dhcp_server_enabled and {
                    'start': str(new['dhcp_start']),
                    'limit': str(new['dhcp_limit']),
                    'leasetime': str(new.setdefault('dhcp_lease_time', 38400)),} or {}
                ifname = const.PORT_MAPPING_LOGIC[new['ifname']]['ifname']
        cmd = [const.CONFIG_BIN_DIR+'set_lan_ip.sh', ifname, ipaddr, netmask]
        cmd_vlan = not untagged and ['-v', str(vid),] or []
        cmd += cmd_vlan
        cmd += ['-z', zone]
        cmd += ['-S',]
        res = self.doit(cmd, 'Change IP address of LAN interface')
        if dhcp_server_enabled:
            cmd = [const.CONFIG_BIN_DIR+'set_dhcp_server.sh', ifname, 
                dhcp_pool['start'], dhcp_pool['limit'], '-l', dhcp_pool['leasetime'],
            ]
        else:
            cmd = [const.CONFIG_BIN_DIR+'disable_dhcp_server.sh', ifname, ]
        cmd += cmd_vlan
        cmd += ['-S',]
        res &= self.doit(cmd)
        return res

    @logcfg
    def remove(self):
        old = self.data
        with ConfigInputEnv(old, 'VLAN configuration'):
            if 'ifname' not in old:
                self.log_warning('unbinded VLAN %s is removed' % (old['id']))
                return True
            else:
                ipaddr, netmask, vid, untagged, zone = old['gateway'], old['netmask'], old['vlan'], old['untagged'], old['security_zone']
                dhcp_server_enabled = old.setdefault('dhcp_server_enable', 0)
                dhcp_pool = dhcp_server_enabled and {
                    'start': str(old['dhcp_start']),
                    'limit': str(old['dhcp_limit']),
                    'leasetime': str(old['dhcp_lease_time']),} or {}
                ifname = const.PORT_MAPPING_LOGIC[old['ifname']]['ifname']
        res = True
        if not untagged:
            cmd = [const.CONFIG_BIN_DIR+'disable_vlan.sh', ifname, ]
            cmd += ['-z', zone]
            cmd += ['-S',]
            res &= self.doit(cmd, 'Disable VLAN interface')
        if dhcp_server_enabled:
            cmd = [const.CONFIG_BIN_DIR+'disable_dhcp_server.sh', ifname, ]
            cmd += not untagged and ['-v', str(vid)] or []
            cmd += ['-S',]
            res &= self.doit(cmd, "Disable DHCP Server")
        return res

    @logcfg
    def change(self):
        self.add()
        return True

    @logcfg
    def post_run(self):
        self.doit(['/etc/init.d/network', 'reload'], 'Restart dnsmasq')
        self.doit(['/etc/init.d/dnsmasq', 'reload'], 'Restart dnsmasq')
        self.doit(['/etc/init.d/firewall', 'reload'], 'Restart dnsmasq')
        return True