#!/usr/bin/env python

import argparse, os, subprocess, re, json, sys
from cfgobjects import CfgSystem, CfgDDNS
from okos_utils import log_crit, log_err, log_warning, log_info, log_debug
import fcntl

class OakmgrCfg(object):
    Templates = [
            CfgSystem(),
            CfgDDNS(),
            ]
    def __init__(self, f=''):
        super(OakmgrCfg, self).__init__()
        self.source = f
        self.objects = None
        if f:
            with open(f, 'r') as cfg:
                fcntl.flock(cfg.fileno(), fcntl.LOCK_SH)
                str = cfg.read()
                try:
                    self._json = json.loads(str, encoding='utf-8')
                except Exception, e:
                    log_info("----->$$$${}".format(str))
        else:
            self._json = {}

    def parse(self):
        self.objects = [self._json and t.parse(self._json) or [] for t in self.Templates]
        return bool(len(self.Templates) == len(self.objects))

    def __sub__(self, old):
        log_debug('Calculate diff from <{old}> to <{new}>'.format(old=old.source, new=self.source))
        diff = OakmgrCfg()
        diff.objects = [t.diff(self.objects[i], old.objects[i]) for i,t in enumerate(diff.Templates)]
        return diff

    def dump(self):
        log_debug('Dump uci configuration files...')

    def run(self):
        log_debug('Start to execute commands...')
        for i,objs in enumerate(self.objects):
            log_debug('\n>>> ' + self.Templates[i].__class__.__name__)
            if not self.Templates[i].pre_run():
                return False
            for o in objs:
                if not o.run():
                    return False
            if not self.Templates[i].post_run():
                return False
        return True

def main(args):
    log_debug(args)
    cur = OakmgrCfg(args.target)
    if not cur.parse():
        log_debug('current configuration parse failed.')
        return 1
    ori = OakmgrCfg(args.original)
    if not ori.parse():
        log_debug('original configuration parse failed.')
        return 2
    diff = cur - ori
    diff.dump()
    if not diff.run():
        return 3
    else:
        return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create diff from current config to original one.')
    parser.add_argument('target', help='Current configuration file')
    parser.add_argument('-o', '--original', type=str, help='Original configuration file')
    #parser.add_argument('-f', '--file', type=str, help='configuration file')
    #parser.add_argument()
    args = parser.parse_args()

    sys.exit(main(args))


