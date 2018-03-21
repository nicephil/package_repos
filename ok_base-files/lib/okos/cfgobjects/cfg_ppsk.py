#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse, os, subprocess, re, json, pprint
from cfg_object import CfgObj
from subprocess import Popen,PIPE
import urllib2

class CfgPPSK(CfgObj):
    def __init__(self):
        super(CfgPPSK, self).__init__('ssid')
    def parse(self, j):
        ssids = j['wlan']['ssids']
        ppsks = [s for s in ssids if s.has_key('ppsk_keys_url')]
        res = [CfgPPSK() for s in ppsks]
        for i,r in enumerate(res):
            d = r.data
            ppsks[i]['__template_id'] = i
            d['ssid'] = ppsks[i]['ssid']
            d['ppsk_keys_url'] = ppsks[i]['ppsk_keys_url']
        return res
    def file_compare_and_action(self, old, new_c):
        ret = False
        old_f = open(old, 'r')
        old_c = old_f.readlines()
        old_f.close()
        for i in old_c:
            if i not in new_c:
                # old special, delete it
                # wpa_cli raw IFNAME=ath10 DEL_WPA_PSK 00:11:22:33:44:5
                pass
        for i in new_c:
            if i not in old_c:
                # new special, add it
                # wpa_cli raw IFNAME=ath10 ADD_WPA_PSK 00:11:22:33:44:5
                pass
        return ret
    def download_file(self, url):
        try:
            response = urllib2.urlopen(url, timeout=3)
            new_c = response.read()
        except Exception as e:
            new_c = None
            print "can't:%s" % url
        return new_c
    def overwrite_file(self, fname, new_c):
        ret = True
        try:
            file = open(fname, 'w')
            file.write(new_c)
        except:
            ret = False
        finally:
            file.close()
        return ret
    def run_cmd(self, cmd):
        try:
            current_process = Popen(cmd, stdout=PIPE,stderr=PIPE,shell=True,cwd='/tmp',preexec_fn=os.setsid) # so that we can kill the process group
            cmd_stdout, cmd_stderr = current_process.communicate()
            cmd_stdout = cmd_stdout.strip()
        except Exception as e:
            cmd_stdout = None
        if cmd_stderr:
            cmd_stdout = None
        return cmd_stdout
    def change(self):
        ret = False
        # 1. wget self.data['ppsk_keys_url'] in new ppsk file
        new_c = self.download_file(self.data['ppsk_keys_url'])
        if not new_c:
            return ret
        # 2. search stid by self.data['ssid'] and find the old ppsk file
        cmd = "uci show wlan_service_template | awk -F'.' '/%s/{print substr($2,16);exit}'" % self.data['ssid']
        stid = self.run_cmd(cmd)
        if not stid:
            return ret
        old_ppsk_keys_file = "/var/run/wpa_psk_file-stid%s" % self.run_cmd(cmd)
        print "ppsk_keys_file:%s" % old_ppsk_keys_file
        # 3. compre the content and update runtime ppsk
        # ret = file_compare_and_action(old_ppsk_keys_file, new_c)
        # 4. update the old file
        ret = self.overwrite_file(old_ppsk_keys_file, new_c)
        # 5. load again key
        cmd = "uci show wireless | awk -F'.' '/%s/{print $2}'" % self.data['ssid']
        aths = self.run_cmd(cmd)
        if not aths:
            return ret
        for ath in aths.split('\n'):
            cmd = "wpa_cli -g /var/run/hostapd/global raw IFNAME=%s DEL_WPA_PSK;wpa_cli -g /var/run/hostapd/global raw IFNAME=%s ADD_WPA_PSK" % (ath, ath)
            out = self.run_cmd(cmd)
            if out:
                return ret
        ret = True
        return ret

