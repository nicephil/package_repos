#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv
from okos_utils import logcfg
#import ubus
from constant import const

class CfgInterface(CfgObj):
    def __init__(self):
        super(CfgInterface, self).__init__()

    @logcfg
    def parse(self, j):
        eths = ('e0','e1','e2','e3')
        res = [CfgInterface() for eth in eths]
        for i, eth in enumerate(eths):
            res[i].data['logic_ifname'] = eth
            try:
                res[i].data.update(j['interfaces'][eth])
            except KeyError as _:
                res[i].data['status'] = 'disabled'
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
        with ConfigInputEnv(new, "Start to change interface [%s] config (type,status,iptype)." % (new['logic_ifname'])):
            if_type = new['type']
            if_status = new['status']
            if_mode = new['ip_type']
        port_mapping = const.PORT_MAPPING_LOGIC
        config_name = port_mapping[new['logic_ifname']]['ifname']
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
        if new['type'] != const.DEV_CONF_PORT_TYPE['lan']:
            self.log_warning('Config LAN port as WAN. <%s>' % (new))
            return False
        if new['ips']:
            ipaddr, netmask = new['ips'][0]['ip'], new['ips'][0]['netmask']
            cmd = [const.CONFIG_BIN_DIR+'set_lan_ip.sh', config_name, ipaddr, netmask]
            self.doit(cmd, 'Change IP address of LAN port')
        if new.setdefault('dhcp_server_enable', 0):
            dhcps_n = {
                    'start': str(new['dhcp_start']),
                    'limit': str(new['dhcp_limit']),
                    'leasetime': str(new['dhcp_lease_time']),
                    }
            cmd = [const.CONFIG_BIN_DIR+'set_dhcp_server.sh', config_name,
                dhcps_n['start'], dhcps_n['limit'],
                '-l', dhcps_n['leasetime'], ]
            return self.doit(cmd, "Change DHCP configuration")
        else:
            cmd = [const.CONFIG_BIN_DIR+'disable_dhcp_server.sh', config_name, ]
            return self.doit(cmd, "DHCP Server is disabled")
        return True

    @logcfg
    def change_wan_config(self, config_name):
        new = self.data
        if new['type'] != const.DEV_CONF_PORT_TYPE['wan']:
            self.log_warning('Config WAN port as LAN. <%s>' % (new))
            return False
        # Enable interface
        if new['status']:
            # For DHCP
            if new['ip_type'] == 0:
                with ConfigInputEnv(new, 'Set DHCP on WAN port %s' % (config_name)):
                    dnss = (new.setdefault('manual_dns',0) and new.setdefault('dnss','')) and new['dnss'] or ''
                    default_route_enable = new.setdefault('default_route_enable', 0)
                    mtu = new.setdefault('mtu', 0)
                cmd = [const.CONFIG_BIN_DIR+'set_wan_dhcp.sh', config_name]
                cmd += dnss and ['-d', dnss] or []
                cmd += default_route_enable and ['-r',] or ['-R',]
                cmd += mtu and ['-m', str(mtu)] or []
                return self.doit(cmd)
            # For static ip
            if new['ip_type'] == 1:
                with ConfigInputEnv(new, 'Set static ip on WAN port %s' % (config_name)):
                    ips = new['ips']
                    dnss = new['dnss']
                    gateway = new['gateway']
                    default_route_enable = new.setdefault('default_route_enable', 0)
                    default_route_ip = default_route_enable and new['default_route_ip'] or ''
                    mtu = new.setdefault('mtu', 0)
                if not dnss:
                    self.log_warning('Set Static IP on WAN port <%s> without DNSs' % (config_name))
                    return False
                ips_str = ','.join(['%s/%s' % (ip['ip'], ip['netmask']) for ip in ips])
                cmd = [const.CONFIG_BIN_DIR+'set_wan_static_ip.sh', config_name, gateway, ips_str, dnss]
                cmd += default_route_ip and ['-r', default_route_ip] or ['-R',]
                cmd += mtu and ['-m', str(mtu)] or []
                return self.doit(cmd)
            # For pppoe
            if new['ip_type'] == 2:
                with ConfigInputEnv(new, 'Set PPPOE on WAN port %s' % (config_name)):
                    pppoe = {'username': new['pppoe_username'],
                            'password': new['pppoe_password'],
                            'keepalive': int(new.setdefault('pppoe_timeout', 30))/5,
                            'keepconnected': new.setdefault('pppoe_keep_connected', 1),
                            }
                    default_route_enable = new.setdefault('default_route_enable', 0)
                    mtu = new.setdefault('mtu', 0)
                cmd = [const.CONFIG_BIN_DIR+'set_wan_pppoe.sh', config_name, pppoe['username'], pppoe['password'], '-k', str(pppoe['keepalive']), ]
                cmd += default_route_enable and ['-r',] or ['-R',]
                cmd += mtu and ['-m', str(mtu)] or []
                return self.doit(cmd)
        # Disable interface
        else:
            cmd = [const.CONFIG_BIN_DIR+'disable_port.sh', config_name, ]
            return self.doit(cmd)
        return True

