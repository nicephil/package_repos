#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ParameterChecker
from okos_utils import logcfg, logchecker
#import ubus
from constant import const

class CfgNetwork(CfgObj):
    def __init__(self, vlan={}, ifs={}):
        super(CfgNetwork, self).__init__()
        self.data.update(vlan)
        if ifs:
            for ifname,ifx in ifs.iteritems():
                if ifx['type'] == const.DEV_CONF_PORT_TYPE['lan']:
                    native_vlan = ifx.setdefault('native_vlan', 1)
                    if vlan['id'] in ifx['local_network_ids']:
                        self.data['ifname'] = ifname
                        self.data['untagged'] = bool(native_vlan == vlan['vlan'])

    @logcfg
    def parse(self, j):
        vlans = j['network'].setdefault('local_networks',[])
        with ConfigParseEnv(vlans, 'VLAN configuration'):
            res = [CfgNetwork(vlan, j['interfaces']) for vlan in vlans]
        return res

    @logchecker('VLAN')
    def _check_gateway_(self, gateway, obj_name=''):
        return True
    @logchecker('VLAN')
    def _check_netmask_(self, netmask, obj_name=''):
        return True
    @logchecker('VLAN')
    def _check_vlanid_(self, vlanid, obj_name=''):
        return True
    @logchecker('VLAN')
    def _check_zone_(self, zone, obj_name=''):
        return bool(zone in const.CONFIG_SECURITY_ZONE)
    @logchecker('VLAN')
    def _check_(self, noop, obj_name=''):
        return True
    
    @logcfg
    def add(self):
        new = self.data
        with ConfigInputEnv(new, 'VLAN config'):
            if 'ifname' not in new:
                self.log_warning('VLAN %s is not bound to any interface' % (new['id']))
                return True
            else:
                #checker = ParameterChecker(new)
                #checker['gateway'] = self._check_gateway_
                #checker['netmask'] = self._check_netmask_
                #checker['vlan'] = self._check_vlanid_
                #checker['untagged'] = self._check_
                #checker['security_zone'] = self._check_zone_
                fmt = {
                    'gateway': self._check_gateway_,
                    'netmask': self._check_netmask_,
                    'vlan': self._check_vlanid_,
                    'untagged': self._check_,
                    'security_zone': self._check_,
                }
                self._entry_ = {k:new[k] for k in fmt}
                if not self.check_para(fmt, self._entry_):
                    return False

                #ipaddr, netmask, vid, untagged, zone = new['gateway'], new['netmask'], new['vlan'], new['untagged'], new['security_zone']
                dhcp_server_enabled = new.setdefault('dhcp_server_enable', 0)
                dhcp_pool = dhcp_server_enabled and {
                    'start': str(new['dhcp_start']),
                    'limit': str(new['dhcp_limit']),
                    'leasetime': str(new.setdefault('dhcp_lease_time', 38400)),} or {}
                ifname = const.PORT_MAPPING_LOGIC[new['ifname']]['ifname']
        cmd = [const.CONFIG_BIN_DIR+'set_lan_ip.sh', ifname, self._entry_['gateway'], self._entry_['netmask'],]
        cmd_vlan = not self._entry_['untagged'] and ['-v', str(self._entry_['vlan']),] or []
        cmd += cmd_vlan
        cmd += ['-z', self._entry_['security_zone']]
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
        with ConfigInputEnv(old, 'VLAN remove'):
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
        self.doit(['/etc/init.d/network', 'reload'], 'Restart network')
        self.doit(['/etc/init.d/dnsmasq', 'reload'], 'Restart dnsmasq')
        return True