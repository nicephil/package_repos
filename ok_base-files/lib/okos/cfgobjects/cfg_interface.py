#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ParameterChecker
from okos_utils import logcfg, logchecker
#import ubus
from constant import const

class CfgInterface(CfgObj):
    def __init__(self, ifname='', ifx={}):
        super(CfgInterface, self).__init__()
        self.data['logic_ifname'] = ifname
        self.data.update(ifx)


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

    @logcfg
    def change(self):
        new = self.data
        self._checker_ = checker = ParameterChecker(new)
        with ConfigInputEnv(new, "Change interface [%s] config (type,status,iptype)." % (new['logic_ifname'])):
            checker['type'] = (None, None)
            checker['status'] = (None, None)
            checker['ip_type'] = (None, None)
            checker['logic_ifname'] = (None, None)
            if not checker.dump():
                return False
        config_name = const.PORT_MAPPING_LOGIC[checker['logic_ifname']]['ifname']
        change_hooks = {
                'e0': self.change_wan_config,
                'e1': self.change_wan_config,
                'e2': self.change_wan_config,
                'e3': self.change_lan_config,
                }
        res = change_hooks[self.data['logic_ifname']](config_name)
        self.log_debug("Change interface [%s] config return (%s)." % (self.data['logic_ifname'], str(res)))
        return res

    @logcfg
    def change_lan_config(self, config_name):
        self.log_info('Execute LAN port config.')
        new = self.data
        if self._checker_['type'] != const.DEV_CONF_PORT_TYPE['lan']:
            self.log_warning('Config LAN port as WAN. <%s>' % (new))
            return False
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
    def change_wan_config(self, config_name):
        new = self.data
        checker = ParameterChecker(new)
        if self._checker_['type'] != const.DEV_CONF_PORT_TYPE['wan']:
            self.log_warning('Config WAN port as LAN. <%s>' % (new))
            return False
        # Enable interface
        if self._checker_['status']:
            # For DHCP
            if self._checker_['ip_type'] == 0:
                with ConfigInputEnv(new, 'Set DHCP on WAN port %s' % (config_name)):
                    checker['manual_dns'] = (None, 0)
                    checker['dnss'] = (None, '')
                    checker['default_route_enable'] = (None, 0)
                    checker['mtu'] = (None, 0)
                    if not checker.dump():
                        return False
                cmd = [const.CONFIG_BIN_DIR+'set_wan_dhcp.sh', config_name]
                cmd += (checker['manual_dns'] and checker['dnss']) and ['-d', checker['dnss'], ] or []
                cmd += checker['default_route_enable'] and ['-r',] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu']] or []
                cmd += ['-S',]
                return self.doit(cmd)
            # For static ip
            if self._checker_['ip_type'] == 1:
                with ConfigInputEnv(new, 'Set static ip on WAN port %s' % (config_name)):
                    checker['ips'] = (None, None)
                    checker['dnss'] = (None, None)
                    checker['gateway'] = (None, None)
                    checker['default_route_enable'] = (None, 0)
                    checker['default_route_ip'] = (None, '')
                    checker['mtu'] = (None, 0)
                    if not checker.dump():
                        return False

                ips_str = ','.join(['%s/%s' % (ip['ip'], ip['netmask']) for ip in checker['ips']])
                cmd = [const.CONFIG_BIN_DIR+'set_wan_static_ip.sh', config_name, checker['gateway'], ips_str, checker['dnss']]
                cmd += (checker['default_route_enable'] and checker['default_route_ip']) and ['-r', checker['default_route_ip']] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu']] or []
                cmd += ['-S',]
                return self.doit(cmd)
            # For pppoe
            if self._checker_['ip_type'] == 2:
                with ConfigInputEnv(new, 'Set PPPOE on WAN port %s' % (config_name)):
                    checker['pppoe_username'] = (None, None)
                    checker['pppoe_password'] = (None, None)
                    checker['pppoe_timeout'] = (None, 30)
                    checker['pppoe_keep_connected'] = (None, 1)
                    checker['default_route_enable'] = (None, 0)
                    checker['mtu'] = (None, 0)
                    if not checker.dump():
                        return False
                cmd = [const.CONFIG_BIN_DIR+'set_wan_pppoe.sh', config_name,
                        checker['pppoe_username'], checker['pppoe_password'], '-k', checker['pppoe_timeout'], ]
                cmd += checker['default_route_enable'] and ['-r',] or ['-R',]
                cmd += checker['mtu'] and ['-m', checker['mtu'],] or []
                cmd += ['-S',]
                return self.doit(cmd)
        # Disable interface
        else:
            cmd = [const.CONFIG_BIN_DIR+'disable_port.sh', config_name, ]
            return self.doit(cmd)
        return True

