#!/usr/bin/env python

import argparse, os, subprocess, re, json
from cfg_object import CfgObj
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit, logcfg
#import ubus
from constant import const

class CfgNetwork(CfgObj):
    def __init__(self):
        super(CfgNetwork, self).__init__()
    
    def _consume(self, vlan, ifs):
        self.data.update(vlan)
        for ifname,ifx in ifs.iteritems():
            native_vlan = ifx.setdefault('native_vlan', 1)
            if vlan['id'] in ifx['local_network_ids']:
                self.data['ifname'] = ifname
                self.data['untagged'] = bool(native_vlan == vlan['vlan'])
        return self

    @logcfg
    def parse(self, j):
        try:
            res = [CfgNetwork()._consume(vlan, j['interfaces']) for vlan in j['network'].setdefault('local_networks',[])]
        except Exception as e:
            self.log_warning('Load VLAN configuration failed.')
            raise e
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
        return True

