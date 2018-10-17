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
    def _check_gateway_(self, input, obj_name=''):
        return True, input
    @logchecker('VLAN')
    def _check_netmask_(self, input, obj_name=''):
        return True, input
    @logchecker('VLAN')
    def _check_vlanid_(self, input, obj_name=''):
        return True, input
    @logchecker('VLAN')
    def _check_zone_(self, input, obj_name=''):
        return bool(input in const.CONFIG_SECURITY_ZONE), input
    @logchecker('VLAN')
    def _check_(self, input, obj_name=''):
        return True, input
    
    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'VLAN config'):
            if 'ifname' not in new:
                self.log_warning('VLAN %s is not bound to any interface' % (new['id']))
                return True
            else:
                checker = ParameterChecker(new)
                checker['gateway'] = (self._check_gateway_, None)
                checker['netmask'] = (self._check_netmask_, None)
                checker['vlan'] = (self._check_vlanid_, None)
                checker['untagged'] = (None, None)
                checker['security_zone'] = (self._check_zone_, None)
                checker['dhcp_server_enable'] = (None, 0)
                if checker['dhcp_server_enable']:
                    checker['dhcp_start'] = (None, None)
                    checker['dhcp_limit'] = (None, None)
                    checker['dhcp_lease_time'] = (None, 38400)
                if not checker.dump():
                    return False
                ifname = const.PORT_MAPPING_LOGIC[new['ifname']]['ifname']
        cmd = [const.CONFIG_BIN_DIR+'set_lan_ip.sh', ifname, checker['gateway'], checker['netmask'],]
        cmd_vlan = not checker['untagged'] and ['-v', str(checker['vlan']),] or []
        cmd += cmd_vlan
        cmd += ['-z', checker['security_zone']]
        cmd += ['-S',]
        res = self.doit(cmd, 'Change IP address of LAN interface')
        if checker['dhcp_server_enable']:
            cmd = [const.CONFIG_BIN_DIR+'set_dhcp_server.sh', ifname, 
                checker['dhcp_start'], checker['dhcp_limit'], '-l', checker['dhcp_lease_time'],
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
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'VLAN remove'):
            if 'ifname' not in old:
                self.log_warning('unbinded VLAN %s is removed' % (old['id']))
                return True
            else:
                checker['vlan'] = (self._check_vlanid_, None)
                checker['untagged'] = (None, None)
                checker['security_zone'] = (self._check_zone_, None)
                checker['dhcp_server_enable'] = (None, 0)
                if not checker.dump():
                    return False
                ifname = const.PORT_MAPPING_LOGIC[old['ifname']]['ifname']
        res = True
        if not checker['untagged']:
            cmd = [const.CONFIG_BIN_DIR+'disable_vlan.sh', ifname, ]
            cmd += ['-z', checker['security_zone'],]
            cmd += ['-S',]
            res &= self.doit(cmd, 'Disable VLAN interface')
        if checker['dhcp_server_enable']:
            cmd = [const.CONFIG_BIN_DIR+'disable_dhcp_server.sh', ifname, ]
            cmd += not checker['untagged'] and ['-v', checker['vlan'], ] or []
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