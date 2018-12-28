#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ParameterChecker
from okos_tools import logcfg, logchecker, log_err, UciStatus, ExecEnv
from constant import const


class CfgInterface(CfgObj):
    differ = 'logic_ifname'
    def __init__(self, ifname=None, ifx=None):
        super(CfgInterface, self).__init__()
        if ifname and ifx:
            self.data.update(ifx)
            self.data['logic_ifname'] = const.PORT_MAPPING_LOGIC[ifname]['ifname']

    @classmethod
    @logcfg
    def parse(cls, j):
        ifs = j['interfaces']
        with ConfigParseEnv(ifs, 'Interfaces configuration', debug=True):
            res = [cls(ifname,ifx) for ifname,ifx in ifs.iteritems()]
        return res

    @logcfg
    def add(self):
        self.change()
        return True

    @logcfg
    def remove(self):
        return True

    def _check_if_type_(self, input):
        if input not in (const.DEV_CONF_PORT_TYPE['wan'], const.DEV_CONF_PORT_TYPE['lan']):
            return False, 'Port type error'
        return True, input
    def _check_lan_if_type_(self, input):
        if input != const.DEV_CONF_PORT_TYPE['lan']:
            return False, 'Try to config LAN port to other mode'
        return True, input
    def _check_wan_if_type_(self, input):
        if input != const.DEV_CONF_PORT_TYPE['wan']:
            return False, 'Try to config WAN port to other mode'
        return True, input

    @logcfg
    def change(self):
        new = self.data
        self._checker_ = checker = ParameterChecker(new)
        with ConfigInputEnv(new, "Change interface [%s] config" % (new['logic_ifname'])):
            checker['type'] = (self._check_if_type_, None)
            checker['status'] = (None, None)
            checker['ip_type'] = (None, None)
            checker['logic_ifname'] = (None, None)
        change_hooks = {
                'wan': self.change_wan_config,
                'wan1': self.change_wan_config,
                'wan2': self.change_wan_config,
                'lan4053': self.change_lan_config,
                }
        res = change_hooks[checker['logic_ifname']]()
        return res

    @logcfg
    def change_lan_config(self):
        new = self.data
        checker = self._checker_
        with ConfigInputEnv('', "Change interface [%s] to LAN" % (new['logic_ifname'])):
            checker['type'] = (self._check_lan_if_type_, None)

        return True

    @logchecker('Interface')
    def _check_dnss_(self, input):
        if not input:
            log_err('Set Static IP without DNSs')
            return False, input
        return True, input
    
    @logchecker('Interface')
    def _check_pppoe_timeout_(self, input):
        input = int(input)/5
        return True, input

    @logcfg
    def change_wan_config(self):
        new = self.data
        checker = self._checker_
        with ConfigInputEnv('', "Change interface [%s] to WAN" % (checker['logic_ifname'])):
            checker['type'] = (self._check_wan_if_type_, None)
        # Enable interface
        if checker['status']:
            # For DHCP
            if checker['ip_type'] == 0:
                with ConfigInputEnv('', 'Set DHCP on WAN port %s' % (checker['logic_ifname'])):
                    checker['manual_dns'] = (None, 0)
                    checker['dnss'] = (None, '')
                    checker['default_route_enable'] = (None, 0)
                    checker['mtu'] = (None, 0)
                    checker['mac_clone'] = (self._check_mac_, '')
                cmd = ['set_wan_dhcp.sh', checker['logic_ifname']]
                cmd += (checker['manual_dns'] and checker['dnss']) and ['-d', checker['dnss'], ] or []
                cmd += checker['default_route_enable'] and ['-r',] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu']] or []
                cmd += ['-S',]
                res = self.doit(cmd)
            # For static ip
            elif checker['ip_type'] == 1:
                with ConfigInputEnv(new, 'Set static ip on WAN port %s' % (checker['logic_ifname'])):
                    checker['ips'] = (None, None)
                    checker['dnss'] = (None, None)
                    checker['gateway'] = (None, None)
                    checker['default_route_enable'] = (None, 0)
                    checker['default_route_ip'] = (None, '')
                    checker['mtu'] = (None, 0)
                    checker['mac_clone'] = (self._check_mac_, '')
                ips_str = ','.join(['%s/%s' % (ip['ip'], ip['netmask']) for ip in checker['ips']])
                cmd = ['set_wan_static_ip.sh', checker['logic_ifname'], checker['gateway'], ips_str, checker['dnss']]
                cmd += (checker['default_route_enable'] and checker['default_route_ip']) and ['-r', checker['default_route_ip']] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu']] or []
                cmd += ['-S',]
                res = self.doit(cmd)
            # For pppoe
            elif checker['ip_type'] == 2:
                with ConfigInputEnv(new, 'Set PPPOE on WAN port %s' % (checker['logic_ifname'])):
                    checker['pppoe_username'] = (None, None)
                    checker['pppoe_password'] = (None, None)
                    checker['pppoe_timeout'] = (None, 30)
                    checker['pppoe_keep_connected'] = (None, 1)
                    checker['default_route_enable'] = (None, 0)
                    checker['mtu'] = (None, 0)
                    checker['mac_clone'] = (self._check_mac_, '')
                cmd = ['set_wan_pppoe.sh', checker['logic_ifname'],
                        checker['pppoe_username'], checker['pppoe_password'], '-k', checker['pppoe_timeout'], ]
                cmd += checker['default_route_enable'] and ['-r',] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu'],] or []
                cmd += ['-S',]
                res = self.doit(cmd)
            else:
                res = False
            if checker['mac_clone']:
                cmd = ['set_mac_clone.sh', 'set', checker['logic_ifname'], 
                        '--mac-clone', checker['mac_clone'],]
                res &= self.doit(cmd)
            return res
        # Disable interface
        else:
            cmd = ['disable_port.sh', checker['logic_ifname'], ]
            return self.doit(cmd)
        return True

    @classmethod
    @logcfg
    def post_run(cls, cargo=None, goods=None):
        cls.add_service('network', cargo)
        cls.add_service('firewall', cargo)
        return True