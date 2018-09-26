#!/usr/bin/env python

import argparse, os, subprocess, re, json
from cfg_object import CfgObj
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit
import ubus

class CfgInterface(CfgObj):
    def __init__(self):
        super(CfgInterface, self).__init__()

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

    def add(self):
        log_debug("add")
        return True
    def remove(self):
        log_debug("remove")
        return True

    def change(self):
        log_debug("change")
        change_hooks = {
                'e0': self.change_wan,
                'e1': self.change_wan,
                'e2': self.change_wan,
                'e3': self.change_lan,
                }
        return change_hooks[self.data['logic_ifname']]()

    def change_lan(self):
        old = self._old.data
        new = self.data
        if old['status'] != new['status']:
            pass
        if old['ips'] != new['ips']:
            try:
                ipaddr, netmask = new['ips'][0]['ip'], new['ips'][0]['netmask']
                subprocess.checkcall(['/lib/okos/bin/set_lan_interface.sh', ipaddr, netmask], shell=True)
            except subprocess.CalledProcessError as _:
                pass
            except Exception as _:
                pass
            pass
        if old['dhcp_server_enable'] != new['dhcp_server_enable']:
            pass
        return True
    def change_wan(self):
        return True
