#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint
from cfgobjects import CfgCapwap, CfgLogServer, CfgNtp, CfgSystem, CfgNetwork, CfgRadio, CfgSsid, CfgPortal, CfgDomainNameSet

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
        self.objects = None
        if f:
            with open(f, 'r') as cfg:
                self._json = json.loads(cfg.read(), encoding='utf-8')
        else:
            self._json = {}

    def parse(self):
        self.objects = [self._json and t.parse(self._json) or [] for t in self.Templates]
        return bool(len(self.Templates) == len(self.objects))

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
        return True

def main(args):
    print args
    cur = OakmgrCfg(args.target)
    if not cur.parse():
        print 'current configuration parse failed.'
        return False
    ori = OakmgrCfg(args.original)
    if not ori.parse():
        print 'original configuration parse failed.'
        return False
    diff = cur - ori
    diff.dump()
    if not diff.run():
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create diff from current config to original one.')
    parser.add_argument('target', help='Current configuration file')
    parser.add_argument('-o', '--original', type=str, help='Original configuration file')
    #parser.add_argument('-f', '--file', type=str, help='configuration file')
    #parser.add_argument()
    args = parser.parse_args()

    main(args)

    print ''
