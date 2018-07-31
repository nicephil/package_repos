#!/usr/bin/env python

import argparse, os, subprocess, re, json
from cfg_object import CfgObj
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit
import ubus

class CfgDDNS(CfgObj):
    def __init__(self):
        super(CfgDDNS, self).__init__('provider')

    def parse(self, j):
        ddnss = j['network']['ddnss']
        res = [CfgDDNS() for d in ddnss]
        for i,r in enumerate(res):
            d = r.data
            d['provider'] = ddnss[i]['provider']
            d['hostname'] = ddnss[i]['hostname']
            d['username'] = ddnss[i]['username']
            d['password'] = ddnss[i]['password']
        return res

    def add(self):
        log_debug("add")
        if not self.data['provider'] or not self.data['username'] or not self.data['password'] or not self.data['hostname']:
            return False
        try:
            # 1. disabled all existing service
            signa = {
                'config':'ddns',
                'type':'service',
                'values':{
                    'enabled':0
                }
            }
            ubus.call('uci', 'set', signa)
            # 2. enabled specific provider
            signa['section'] = self.data['provider'].replace('.','_')
            signa['values'] = {
                'username':self.data['username'],
                'password':self.data['password'],
                'domain':self.data['hostname'],
                'enabled':1
            }
            ubus.call('uci','set',signa)
            # 3. commit the change
            signa={'config':'ddns'}
            ubus.call('uci', 'commit', signa)

        except Exception, e:
            log_err("add ddns gets failed,{}".format(e))
            return False
        return True

    def change(self):
        log_debug("change")
        self.add()
        return True

    def remove(self):
        log_debug("remove")

    def post_run(self):
        log_debug('post_run')
        self.restart_service()
        return True

    def restart_service(self):
        log_debug("post_run")
        cmd = "/etc/init.d/ddns restart"
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False

