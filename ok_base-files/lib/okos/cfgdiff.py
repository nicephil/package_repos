#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint

class CfgObj(object):
    def __init__(self, differ=None):
        super(CfgObj, self).__init__()
        self.action = None
        self.name = self.__class__.__name__
        self.differ = differ
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
        print self.name + ' Parser interface called.'
    def add(self):
        print self.name + ' add interface called.'
        pprint.pprint(self.data)
    def remove(self):
        print self.name + ' remove interface called.'
        pprint.pprint(self.data)
    def change(self):
        print self.name + ' change interface called.'
        pprint.pprint(self.data)
    def pre_run(self):
        print self.name + ' pre-run interface called.'
    def post_run(self):
        print self.name + ' post-run interface called.'
    def diff(self, new, old):
        differ = self.differ
        if not differ:
            return new
        news = {n.data[differ] for n in new}
        olds = {o.data[differ] for o in old}
        if news == olds:
            return new
        else:
            change = [n.change_op() for c in news & olds for n in new if c == n.data[differ]]
            add = [n.add_op() for c in news - olds for n in new if c == n.data[differ]]
            remove = [n.remove_op() for c in olds - news for n in old if c == n.data[differ]]
            return remove + add + change

###############################################################################
class CfgLogServer(CfgObj):
    def __init__(self):
        super(CfgLogServer, self).__init__()
    def parse(self, j):
        res = [CfgLogServer(),]
        d = res[0].data
        log = j['server']['log']
        d['enabled'] = bool(log['enabled'])
        d['server'] = log['server']
        d['level'] = log['log_server_level']
        return res

class CfgSystem(CfgObj):
    def __init__(self):
        super(CfgSystem, self).__init__()
    def parse(self, j):
        res = CfgSystem()
        d = res.data
        system = j['mgmt']['system']
        d['hostname'] = system['hostname']
        d['zone'] = system['zone']
        d['location'] = system['location']
        d['country_code'] = system['country_code']
        d['domain_name'] = system['domain_name']
        d['auth_url'] = system['auth_url']
        return [res,]

class CfgNtp(CfgObj):
    def __init__(self):
        super(CfgNtp, self).__init__()
    def parse(self, j):
        res = CfgNtp()
        d = res.data
        ntp = j['server']['ntp']
        d['enabled'] = bool(ntp['enabled'])
        d['period'] = ntp['period']
        d['servers'] = ntp['servers']
        return [res,]

class CfgCapwap(CfgObj):
    def __init__(self):
        super(CfgCapwap, self).__init__()
    def parse(self, j):
        res = CfgCapwap()
        d = res.data
        capwap = j['server']['capwap']
        d['enabled'] = bool(capwap['enabled'])
        d['master'] = capwap['master_server']
        d['mtu'] = capwap['mtu']
        d['control_port'] = capwap['control_port']
        d['echo_interval'] = capwap['echo_interval']
        return [res,]

class CfgNetwork(CfgObj):
    def __init__(self):
        super(CfgNetwork, self).__init__('vlanid')
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

class CfgSsid(CfgObj):
    def __init__(self):
        super(CfgSsid, self).__init__('ssid')
    def parse(self, j):
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

class CfgRadio(CfgObj):
    def __init__(self):
        super(CfgRadio, self).__init__('id')
    def parse(self, j):
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

class CfgPortal(CfgObj):
    def __init__(self):
        super(CfgPortal, self).__init__('scheme')
    def parse(self, j):
        portals = j['wlan']['portal_schemes']
        res = [CfgPortal() for i in range(0, len(portals))]
        for i,r in enumerate(res):
            d = r.data
            p = portals[i]
            d['scheme'] = p['scheme']
            d['enabled'] = bool(p['enable'])
            d['url'] = p['url']
            d['auth_server'] = p['auth_ip']
            d['whitelist_ip'] = p['whitelist_ip']
            d['domain_set_name'] = p['domain_set_name']
        return res

class CfgDomainNameSet(CfgObj):
    def __init__(self):
        super(CfgDomainNameSet, self).__init__('name')
    def parse(self, j):
        dns = j['wlan']['domain_sets']
        res = [CfgDomainNameSet() for i in range(0, len(dns))]
        for i,r in enumerate(res):
            d = r.data
            dn = dns[i]
            d['name'] = dn['name']
            d['keys'] = dn['keys']
        return res
###############################################################################
class OakmgrCfg(object):
    Templates = [
            CfgCapwap(),
            CfgLogServer(),
            CfgSystem(),
            CfgNtp(),
            CfgRadio(),
            CfgSsid(),
            CfgNetwork(),
            CfgPortal(),
            CfgDomainNameSet(),
            ]
    def __init__(self, f=''):
        super(OakmgrCfg, self).__init__()
        self.source = f
        if f:
            with open(f, 'r') as cfg:
                self._json = json.loads(cfg.read(), encoding='utf-8')
        else:
            self._json = {}
        self._parse_()

    def _parse_(self):
        self.objects = [self._json and t.parse(self._json) or [] for t in self.Templates]

    def __sub__(self, old):
        print 'Calculate diff from <{old}> to <{new}>'.format(old=old.source, new=self.source)
        diff = OakmgrCfg()
        diff.objects = [t.diff(self.objects[i], old.objects[i]) for i,t in enumerate(diff.Templates)]
        return diff

    def dump(self):
        print 'Dump uci configuration files...'

    def run(self):
        print 'Start to execute commands...'
        for i,objs in enumerate(self.objects):
            print '\n>>> ' + self.Templates[i].__class__.__name__
            self.Templates[i].pre_run()
            for o in objs:
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
