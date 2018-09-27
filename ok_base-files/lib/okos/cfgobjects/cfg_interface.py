#!/usr/bin/env python

import argparse, os, subprocess, re, json
from cfg_object import CfgObj
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit, logit
import ubus
from constant import const

class CfgInterface(CfgObj):
    def __init__(self):
        super(CfgInterface, self).__init__()

    @logit
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

    @logit
    def add(self):
        self.change()
        return True

    @logit
    def remove(self):
        return True

    @logit
    def change(self):
        log_debug("Start to change interface [%s] config." % (self.data['logic_ifname']))
        change_hooks = {
                'e0': self.change_wan_config,
                'e1': self.change_wan_config,
                'e2': self.change_wan_config,
                'e3': self.change_lan_config,
                }
        res = change_hooks[self.data['logic_ifname']]()
        log_debug("Change interface [%s] config return (%s)." % (self.data['logic_ifname'], str(res)))
        return res

    def change_lan_config(self):
        log_info('Execute LAN port config.')
        new = self.data
        if new['type'] != const.DEV_CONF_PORT_TYPE['lan']:
            log_warning('Config LAN port as WAN. <%s>' % (new))
            return False
        if new['ips']:
            ipaddr, netmask = new['ips'][0]['ip'], new['ips'][0]['netmask']
            log_info('Change IP address of LAN port %s/%s' % (ipaddr, netmask))
            self.doit([const.CONFIG_BIN_DIR+'set_lan_ip.sh', ipaddr, netmask])
        if new['dhcp_server_enable']:
            dhcps_n = {
                    'start': str(new['dhcp_start']),
                    'limit': str(new['dhcp_limit']),
                    'leasetime': str(new['dhcp_lease_time']),
                    }
            log_info("Change DHCP configuration %s" % (dhcps_n))
            self.doit([const.CONFIG_BIN_DIR+'set_dhcp_server.sh', dhcps_n['start'], dhcps_n['limit'], dhcps_n['leasetime']])
        else:
            self.doit([const.CONFIG_BIN_DIR+'disable_dhcp_server.sh',])
        return True

    def change_wan_config(self):
        log_info('Execute WAN port config.')
        new = self.data
        if new['type'] != const.DEV_CONF_PORT_TYPE['wan']:
            log_warning('Config WAN port as LAN. <%s>' % (new))
            return False
        # Enable interface
        if new['status']:
            dnss = new['manual_dns'] and new['dnss'] or ''
            # For DHCP
            if new['ip_type'] == 0:
                pass
            # For static ip
            if new['ip_type'] == 1:
                ips = new['ips']
                pass
            # For pppoe
            if new['ip_type'] = 2:
                pppoe = {'username': new['pppoe_username'],
                        'password': new['pppoe_password'],
                        'timeout': new['pppoe_timeout'],
                        'keepalive': new['pppoe_keep_connected'],
                        }
                pass
        # Disable interface
        else:
            pass
        return True
