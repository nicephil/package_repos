#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint

class CfgObj(object):
    def __init__(self, name):
        super(CfgObj, self).__init__()
        self.action = None
        self.name = name
        self.data = {}
        self.run = None
        self.change_op()
    def __eq__(self, other):
        return False
    def clear_action(self):
        self.action = None
        self.run = None
    def add_op(self):
        self.action = 'ADD'
        self.run = self.add
        return self
    def remove_op(self):
        self.action = 'REMOVE'
        self.run = self.remove
        return self
    def change_op(self):
        self.action = 'CHANGE'
        self.run = self.change
        return self
    def parse(self, j):
        print 'CfgObj Parser interface called.'
    def diff(self, new, old):
        print 'CfgObj diff interface called.'
        return new 
    def add(self):
        print 'CfgObj add interface called.'
    def remove(self):
        print 'CfgObj remove interface called.'
    def change(self):
        print 'CfgObj change interface called.'
    def pre_run(self):
        print 'CfgObj pre-run interface called.'
    def post_run(self):
        print 'CfgObj post-run interface called.'
    def _diff_by_item_(self, new, old, name):
        print 'CfgObj standard diff interface called.'
        news = {n.data[name] for n in new}
        olds = {o.data[name] for o in old}
        if news == olds:
            return new
        else:
            change = [n.change_op() for c in news & olds for n in new if c == n.data[name]]
            add = [n.add_op() for c in news - olds for n in new if c == n.data[name]]
            remove = [n.remove_op() for c in olds - news for n in old if c == n.data[name]]
            return remove + add + change

class CfgLogServer(CfgObj):
    def __init__(self):
        super(CfgLogServer, self).__init__('CfgLogServer')
    def parse(self, j):
        '''It should be a CLASS method'''
        print 'CfgLogServer Parser called.'
        res = CfgLogServer()
        d = res.data
        log = j['server']['log']
        d['enabled'] = bool(log['enabled'])
        d['server'] = log['server']
        d['level'] = log['log_server_level']
        return [res,]
    def change(self):
        print 'Set Log Server'
        pprint.pprint(self.data)
        print '/etc/init.d/boot restart'

class CfgNetwork(CfgObj):
    def __init__(self):
        super(CfgNetwork, self).__init__('CfgNetwork')
    def parse(self, j):
        ports = j['ports']
        ssids = j['wlan']['ssids']
        vlans = list({p['pvlan'] for p in ports if p['radio'] >= 0})
        res = [CfgNetwork() for v in vlans]
        for i,r in enumerate(res):
            d = r.data
            d['vlanid'] = vlans[i]
            d['ports'] = ['ath'+str(p['radio'])+str(s['__template_id'])
                for p in ports if p['radio'] >= 0 if p['pvlan'] == vlans[i]
                for s in ssids if s['ssid'] == p['name']]
        return res
    def diff(self, new, old):
        print 'CfgNetwork diff called.'
        return self._diff_by_item_(new, old, 'vlanid')
    def change(self):
        print 'Change CfgNetwork'
        pprint.pprint(self.data)
    def add(self):
        print 'Add CfgNetwork'
        pprint.pprint(self.data)
    def remove(self):
        print 'remove CfgNetwork'
        pprint.pprint(self.data)

class CfgSsid(CfgObj):
    def __init__(self):
        super(CfgSsid, self).__init__('CfgSsid')
    def parse(self, j):
        print 'CfgSsid Parser called.'
        ssids = j['wlan']['ssids']
        res = [CfgSsid() for s in ssids]
        for i,r in enumerate(res):
            d = r.data
            ssids[i]['__template_id'] = i
            d['ssid'] = ssids[i]['ssid']
            d['type'] = ssids[i]['type']
            d['beacon_ssid_hide'] = ssids[i]['ssid_hide']
            d['client_max'] = ssids[i]['client_max']
            d['ptk_lifetime'] = ssids[i]['ptk_lifetime']
            d['ptk_enabled'] = ssids[i]['ptk_enabled']
            d['gtk_lifetime'] = ssids[i]['gtk_lifetime']
            d['gtk_enabled'] = ssids[i]['gtk_enabled']
            d['bandwidth_priority'] = ssids[i]['bandwidth_priority']
            d['client_isolation'] = ssids[i]['client_isolation']
            d['psk_key'] = ssids[i].setdefault('key', '')
            d['portal_scheme'] = ssids[i]['portal_scheme']
            d['radios'] = [p['radio'] for p in j['ports'] if p['name'] == d['ssid']]
            d['vlan'] = {p['pvlan'] for p in j['ports'] if p['name'] == d['ssid']}
        return res
    def diff(self, new, old):
        print 'CfgSsid diff called.'
        return self._diff_by_item_(new, old, 'ssid')
    def change(self):
        print 'Set CfgSsid'
        pprint.pprint(self.data)
    def add(self):
        print 'Add CfgSsid'
        pprint.pprint(self.data)
    def remove(self):
        print 'Remove CfgSsid'
        pprint.pprint(self.data)

class CfgRadio(CfgObj):
    def __init__(self):
        super(CfgRadio, self).__init__('CfgRadio')
    def parse(self, j):
        print 'CfgRadio Parser called.'
        ifs = { c['name']: bool(c['enabled']) for c in j['interfaces'] if c['name'].find('wifi') >= 0}
        radios = j['wlan']['radios']
        res = [CfgRadio() for r in radios]
        for i,r in enumerate(res):
            d = r.data
            radio = radios[i]
            d['id'] = radio['id']
            d['enabled'] = ifs['wifi'+str(d['id'])]
            d['hwmode'] = radio['mode']
            d['channel'] = radio['channel']
            d['bandwidth'] = radio['bandwidth']
            d['txpower'] = radio['max_power']
            d['client_max'] = radio['client_max']
        return res
    def diff(self, new, old):
        print 'CfgRadio diff called.'
        return self._diff_by_item_(new, old, 'id')

    def change(self):
        print 'Set Radios'
        pprint.pprint(self.data)

###############################################################################
class OakmgrCfg(object):
    Templates = [
            CfgLogServer(),
            CfgRadio(),
            CfgSsid(),
            CfgNetwork(),
            ]
    def __init__(self, f=None):
        super(OakmgrCfg, self).__init__()
        if f:
            with open(f, 'r') as cfg:
                self._json = json.loads(cfg.read(), encoding='utf-8')
        else:
            self._json = {}
        self._parse_()

    def _parse_(self):
        if self._json:
            self.objects = [{'name':t.name, 'objs':t.parse(self._json)} for t in self.Templates]
        else:
            self.objects = [{'name':t.name, 'objs':[]} for t in self.Templates]

    def __sub__(self, old):
        print 'Calculate diff from {old} to {new}'.format(old=old, new=self)
        diff = OakmgrCfg()
        for i,t in enumerate(diff.Templates):
            diff.objects[i]['objs'] = t.diff(self.objects[i]['objs'], old.objects[i]['objs'])
        return diff

    def dump(self):
        print 'Dump uci configuration files...'

    def run(self):
        print 'Start to execute commands...'
        for i,objs in enumerate(self.objects):
            print '>>>' + objs['name']
            self.Templates[i].pre_run()
            for o in objs['objs']:
                o.run()
            self.Templates[i].post_run()

def main(args):
    print args
    cur = OakmgrCfg(args.target)
    ori = OakmgrCfg(args.original)
    diff = cur - ori
    diff.dump()
    diff.run()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create diff from current config to original one.')
    parser.add_argument('target', help='Current configuration file')
    parser.add_argument('-o', '--original', type=str, help='Original configuration file')
    #parser.add_argument('-f', '--file', type=str, help='configuration file')
    #parser.add_argument()
    args = parser.parse_args()

    main(args)

    print ''
