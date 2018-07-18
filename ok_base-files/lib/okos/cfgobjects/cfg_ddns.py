#!/usr/bin/env python

import argparse, os, subprocess, re, json
from cfg_object import CfgObj
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit

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
        sed_enable = r"'/server=[^, ]*{provider}/s/^#//'".format(provider=self.data['provider'])
        sed_username  = r"'/server=[^, ]*{provider}/s/login=[^, ]*, /login={username}, /'".format(provider=self.data['provider'], username=self.data['username'])
        sed_password  = r"'/server=[^, ]*{provider}/s/password=[^ ]* /password={password} /'".format(provider=self.data['provider'], password=self.data['password'])
        sed_hostname = r"'/server=[^, ]*{provider}/s/[^ ]*$/{hostname}/'".format(provider=self.data['provider'], hostname=self.data['hostname'])
        cmd = r"sed -i -e {} -e {} -e {} -e {} /etc/ddclient.conf".format(sed_enable, sed_username, sed_password, sed_hostname)
        log_debug("===>{}".format(cmd))
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False

    def change(self):
        log_debug("change")
        self.add()
        return True

    def remove(self):
        log_debug("remove")
        sed_disable = "'/server=.*{provider}.* {hostname}/s/^/#&/'".format(provider=self.data['provider'], hostname=self.data['hostname'])
        cmd = r"sed -i -e {} /etc/ddclient.conf".format(sed_disable)
        log_debug("===>{}".format(cmd))
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False

    def post_run(self):
        log_debug('post_run')
        self.restart_service()
        return True

    def restart_service(self):
        log_debug("post_run")
        cmd = "systemctl restart ddclient"
        ret = subprocess.call(cmd, shell=True)
        if ret == 0:
            return True
        else:
            return False

