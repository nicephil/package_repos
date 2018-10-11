#!/usr/bin/env python

import argparse, os, subprocess, re, json
from cfg_object import CfgObj
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit, logcfg
import ubus
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
        log_debug("[Config] Start to change interface [%s] config." % (self.data['logic_ifname']))
        new = self.data
        if new.setdefault('type', -1) == -1:
            log_warning('[Config] Config port TYPE as nothing <%s>' % (new))
            return False
        if new.setdefault('status', -1) == -1:
            log_warning('[Config] Config port MODE as nothing <%s>' % (new))
            return False
        if new.setdefault('ip_type', -1) == -1:
            log_warning('[Config] Config port IP TYPE as nothing <%s>' % (new))
            return False
        port_mapping = const.PORT_MAPPING_LOGIC
        config_name = port_mapping[new['logic_ifname']]['ifname']
        log_debug('[Config] config name of %s is %s' % (self.data['logic_ifname'], config_name))
        change_hooks = {
                'e0': self.change_wan_config,
                'e1': self.change_wan_config,
                'e2': self.change_wan_config,
                'e3': self.change_lan_config,
                }
        try:
            res = change_hooks[self.data['logic_ifname']](config_name)
        except Exception as e:
            log_warning('[Config] change_hooks() failed with error %s' % (str(e)))
            log_debug('[Config] configuration:\n%s\n' % (new))
            return False
        log_debug("[Config] Change interface [%s] config return (%s)." % (self.data['logic_ifname'], str(res)))
        return res

    @logcfg
    def change_lan_config(self, config_name):
        log_info('[Config] Execute LAN port config.')
        new = self.data
        if new['type'] != const.DEV_CONF_PORT_TYPE['lan']:
            log_warning('[Config] Config LAN port as WAN. <%s>' % (new))
            return False
        if new['ips']:
            ipaddr, netmask = new['ips'][0]['ip'], new['ips'][0]['netmask']
            log_info('[Config] Change IP address of LAN port %s/%s' % (ipaddr, netmask))
            self.doit([const.CONFIG_BIN_DIR+'set_lan_ip.sh', config_name, ipaddr, netmask])
        if new['dhcp_server_enable']:
            dhcps_n = {
                    'start': str(new['dhcp_start']),
                    'limit': str(new['dhcp_limit']),
                    'leasetime': str(new['dhcp_lease_time']),
                    }
            log_info("[Config] Change DHCP configuration %s" % (dhcps_n))
            cmd = [const.CONFIG_BIN_DIR+'set_dhcp_server.sh', config_name,
                dhcps_n['start'], dhcps_n['limit'],
                '-l', dhcps_n['leasetime'], ]
            return self.doit(cmd)
        else:
            log_info("[Config] DHCP Server is disabled")
            cmd = [const.CONFIG_BIN_DIR+'disable_dhcp_server.sh', config_name, ]
            return self.doit(cmd)
        return True

    @logcfg
    def change_wan_config(self, config_name):
        new = self.data
        if new['type'] != const.DEV_CONF_PORT_TYPE['wan']:
            log_warning('[Config] Config WAN port as LAN. <%s>' % (new))
            return False
        # Enable interface
        if new['status']:
            # For DHCP
            if new['ip_type'] == 0:
                log_debug('[Config] Set DHCP on WAN port %s' % (config_name))
                try:
                    dnss = (new.setdefault('manual_dns',0) and new.setdefault('dnss','')) and new['dnss'] or ''
                    default_route_enable = new.setdefault('default_route_enable', 0)
                    mtu = new.setdefault('mtu', 0)
                except Exception as e:
                    log_warning('[Config] Acquire parameter failed with error %s' % (str(e)))
                    log_debug('[Config] configuration:\n%s\n' % (new))
                    return False
                cmd = [const.CONFIG_BIN_DIR+'set_wan_dhcp.sh', config_name]
                cmd += dnss and ['-d', dnss] or []
                cmd += default_route_enable and ['-r',] or ['-R',]
                cmd += mtu and ['-m', str(mtu)] or []
                return self.doit(cmd)
            # For static ip
            if new['ip_type'] == 1:
                log_debug('[Config] Set static ip on WAN port %s' % (config_name))
                try:
                    ips = new['ips']
                    dnss = new['dnss']
                    gateway = new['gateway']
                    default_route_enable = new.setdefault('default_route_enable', 0)
                    default_route_ip = default_route_enable and new['default_route_ip'] or ''
                    mtu = new.setdefault('mtu', 0)
                except Exception as e:
                    log_warning('[Config] Acquire parameter failed with error %s' % (str(e)))
                    log_debug('[Config] configuration:\n%s\n' % (new))
                    return False

                if not dnss:
                    log_warning('[Config] Set Static IP on WAN port <%s> without DNSs' % (config_name))
                    return False
                log_info("[Config] Set Static IP on WAN port <%s>" % (config_name))
                ips_str = ','.join(['%s/%s' % (ip['ip'], ip['netmask']) for ip in ips])
                log_debug('[Config] ip list %s' % (ips_str))
                cmd = [const.CONFIG_BIN_DIR+'set_wan_static_ip.sh', config_name, gateway, ips_str, dnss]
                cmd += default_route_ip and ['-r', default_route_ip] or ['-R',]
                cmd += mtu and ['-m', str(mtu)] or []
                return self.doit(cmd)
            # For pppoe
            if new['ip_type'] == 2:
                log_debug('[Config] Set PPPOE on WAN port %s' % (config_name))
                try:
                    pppoe = {'username': new['pppoe_username'],
                            'password': new['pppoe_password'],
                            'keepalive': int(new.setdefault('pppoe_timeout', 30))/5,
                            'keepconnected': new.setdefault('pppoe_keep_connected', 1),
                            }
                    default_route_enable = new.setdefault('default_route_enable', 0)
                    mtu = new.setdefault('mtu', 0)
                except Exception as e:
                    log_warning('[Config] Acquire parameter failed with error %s' % (str(e)))
                    log_debug('[Config] configuration:\n%s\n' % (new))
                    return False
                cmd = [const.CONFIG_BIN_DIR+'set_wan_pppoe.sh', config_name, pppoe['username'], pppoe['password'], '-k', str(pppoe['keepalive']), ]
                cmd += default_route_enable and ['-r',] or ['-R',]
                cmd += mtu and ['-m', str(mtu)] or []
                return self.doit(cmd)
        # Disable interface
        else:
            cmd = [const.CONFIG_BIN_DIR+'disable_port.sh', config_name, ]
            return self.doit(cmd)
        return True

