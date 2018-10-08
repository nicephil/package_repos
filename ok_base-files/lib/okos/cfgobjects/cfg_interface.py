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
        change_hooks = {
                'e0': self.change_wan_config,
                'e1': self.change_wan_config,
                'e2': self.change_wan_config,
                'e3': self.change_lan_config,
                }
        res = change_hooks[self.data['logic_ifname']]()
        log_debug("[Config] Change interface [%s] config return (%s)." % (self.data['logic_ifname'], str(res)))
        return res

    @logcfg
    def change_lan_config(self):
        log_info('[Config] Execute LAN port config.')
        new = self.data
        if new['type'] != const.DEV_CONF_PORT_TYPE['lan']:
            log_warning('[Config] Config LAN port as WAN. <%s>' % (new))
            return False
        if new['ips']:
            ipaddr, netmask = new['ips'][0]['ip'], new['ips'][0]['netmask']
            log_info('[Config] Change IP address of LAN port %s/%s' % (ipaddr, netmask))
            self.doit([const.CONFIG_BIN_DIR+'set_lan_ip.sh', ipaddr, netmask])
        if new['dhcp_server_enable']:
            dhcps_n = {
                    'start': str(new['dhcp_start']),
                    'limit': str(new['dhcp_limit']),
                    'leasetime': str(new['dhcp_lease_time']),
                    }
            log_info("[Config] Change DHCP configuration %s" % (dhcps_n))
            self.doit([const.CONFIG_BIN_DIR+'set_dhcp_server.sh', dhcps_n['start'], dhcps_n['limit'], dhcps_n['leasetime']])
        else:
            log_info("[Config] DHCP Server is disabled")
            self.doit([const.CONFIG_BIN_DIR+'disable_dhcp_server.sh',])
        return True

    @logcfg
    def change_wan_config(self):
        new = self.data
        logic_name = new['logic_ifname']
        if new['type'] != const.DEV_CONF_PORT_TYPE['wan']:
            log_warning('[Config] Config WAN port as LAN. <%s>' % (new))
            return False
        # Enable interface
        port_mapping = const.PORT_MAPPING_LOGIC
        if new['status']:
            # For DHCP
            if new['ip_type'] == 0:
                log_debug('[Config] Set DHCP on WAN port %s' % (logic_name))
                #new['manual_dns'] = 1
                try:
                    dnss = (new['manual_dns'] and new['dnss']) and new['dnss'] or ''
                except Exception as e:
                    log_warning('[Config] Acquire parameter failed with error %s' % (str(e)))
                    log_debug('[Config] configuration:\n%s\n' % (new))
                    return False
                self.doit([const.CONFIG_BIN_DIR+'set_wan_dhcp.sh', port_mapping[logic_name]['ifname'], dnss])
                return True
            # For static ip
            if new['ip_type'] == 1:
                log_debug('[Config] Set static ip on WAN port %s' % (logic_name))
                try:
                    ips = new['ips']
                    dnss = new['dnss']
                    gateway = new['gateway']
                except Exception as e:
                    log_warning('[Config] Acquire parameter failed with error %s' % (str(e)))
                    log_debug('[Config] configuration:\n%s\n' % (new))
                    return False

                if not dnss:
                    log_warning('[Config] Set Static IP on WAN port <%s> without DNSs' % (logic_name))
                    return False
                log_info("[Config] Set Static IP on WAN port <%s>" % (logic_name))
                ips_str = ','.join(['%s/%s' % (ip['ip'], ip['netmask']) for ip in ips])
                log_debug('[Config] ip list %s' % (ips_str))
                self.doit([const.CONFIG_BIN_DIR+'set_wan_static_ip.sh', port_mapping[logic_name]['ifname'], gateway, ips_str, dnss])
                return True
            # For pppoe
            if new['ip_type'] == 2:
                pppoe = {'username': new['pppoe_username'],
                        'password': new['pppoe_password'],
                        'timeout': new['pppoe_timeout'],
                        'keepalive': new['pppoe_keep_connected'],
                        }
                pass
        # Disable interface
        else:
            self.doit([const.CONFIG_BIN_DIR+'disable_wan_port.sh', logic_name])
        return True

