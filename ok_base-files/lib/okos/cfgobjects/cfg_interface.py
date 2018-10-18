#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ParameterChecker
from okos_utils import logcfg, logchecker
#import ubus
from constant import const

class CfgInterface(CfgObj):
    def __init__(self, ifname='', ifx={}):
        super(CfgInterface, self).__init__('logic_ifname')
        self.data.update(ifx)
        if ifname and ifx:
            self.data['logic_ifname'] = const.PORT_MAPPING_LOGIC[ifname]['ifname']

    @logcfg
    def parse(self, j):
        ifs = j.setdefault('interfaces', {})
        with ConfigParseEnv(ifs, 'Interfaces configuration'):
            res = [CfgInterface(ifname,ifx) for ifname,ifx in ifs.iteritems()]
        return res

    @logcfg
    def add(self):
        self.change()
        return True

    @logcfg
    def remove(self):
        return True

    @logchecker('Interface')
    def _check_if_type_(self, input, obj_name=''):
        if input not in (const.DEV_CONF_PORT_TYPE['wan'], const.DEV_CONF_PORT_TYPE['lan']):
            return False, 'Port type error'
        return True, input
    @logchecker('Interface')
    def _check_lan_if_type_(self, input, obj_name=''):
        if input != const.DEV_CONF_PORT_TYPE['lan']:
            return False, 'Try to config LAN port to other mode'
        return True, input
    @logchecker('Interface')
    def _check_wan_if_type_(self, input, obj_name=''):
        if input != const.DEV_CONF_PORT_TYPE['wan']:
            return False, 'Try to config WAN port to other mode'
        return True, input

    @logcfg
    def change(self):
        new = self.data
        self._checker_ = checker = ParameterChecker(new)
        with ConfigInputEnv(new, "Change interface [%s] config (type,status,iptype)." % (new['logic_ifname'])):
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
        self.log_debug("Change interface [%s] config return (%s)." % (checker['logic_ifname'], str(res)))
        return res

    @logcfg
    def change_lan_config(self):
        self.log_info('Execute LAN port config.')
        new = self.data
        checker = self._checker_
        with ConfigInputEnv(new, "Change interface [%s] to LAN" % (new['logic_ifname'])):
            checker['type'] = (self._check_lan_if_type_, None)

        return True

    @logchecker('Interface')
    def _check_dnss_(self, input, obj_name=''):
        if not input:
            self.log_warning('Set Static IP without DNSs')
            return False, input
        return True, input
    
    @logchecker('Interface')
    def _check_pppoe_timeout_(self, input, obj_name=''):
        input = int(input)/5
        return True, input

    @logcfg
    def change_wan_config(self):
        new = self.data
        checker = self._checker_
        # Enable interface
        if checker['status']:
            # For DHCP
            if checker['ip_type'] == 0:
                with ConfigInputEnv(new, 'Set DHCP on WAN port %s' % (checker['logic_ifname'])):
                    checker['manual_dns'] = (None, 0)
                    checker['dnss'] = (None, '')
                    checker['default_route_enable'] = (None, 0)
                    checker['mtu'] = (None, 0)
                cmd = [const.CONFIG_BIN_DIR+'set_wan_dhcp.sh', checker['logic_ifname']]
                cmd += (checker['manual_dns'] and checker['dnss']) and ['-d', checker['dnss'], ] or []
                cmd += checker['default_route_enable'] and ['-r',] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu']] or []
                cmd += ['-S',]
                return self.doit(cmd)
            # For static ip
            if checker['ip_type'] == 1:
                with ConfigInputEnv(new, 'Set static ip on WAN port %s' % (checker['logic_ifname'])):
                    checker['ips'] = (None, None)
                    checker['dnss'] = (None, None)
                    checker['gateway'] = (None, None)
                    checker['default_route_enable'] = (None, 0)
                    checker['default_route_ip'] = (None, '')
                    checker['mtu'] = (None, 0)
                ips_str = ','.join(['%s/%s' % (ip['ip'], ip['netmask']) for ip in checker['ips']])
                cmd = [const.CONFIG_BIN_DIR+'set_wan_static_ip.sh', checker['logic_ifname'], checker['gateway'], ips_str, checker['dnss']]
                cmd += (checker['default_route_enable'] and checker['default_route_ip']) and ['-r', checker['default_route_ip']] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu']] or []
                cmd += ['-S',]
                return self.doit(cmd)
            # For pppoe
            if checker['ip_type'] == 2:
                with ConfigInputEnv(new, 'Set PPPOE on WAN port %s' % (checker['logic_ifname'])):
                    checker['pppoe_username'] = (None, None)
                    checker['pppoe_password'] = (None, None)
                    checker['pppoe_timeout'] = (None, 30)
                    checker['pppoe_keep_connected'] = (None, 1)
                    checker['default_route_enable'] = (None, 0)
                    checker['mtu'] = (None, 0)
                cmd = [const.CONFIG_BIN_DIR+'set_wan_pppoe.sh', checker['logic_ifname'],
                        checker['pppoe_username'], checker['pppoe_password'], '-k', checker['pppoe_timeout'], ]
                cmd += checker['default_route_enable'] and ['-r',] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu'],] or []
                cmd += ['-S',]
                return self.doit(cmd)
        # Disable interface
        else:
            cmd = [const.CONFIG_BIN_DIR+'disable_port.sh', checker['logic_ifname'], ]
            return self.doit(cmd)
        return True

