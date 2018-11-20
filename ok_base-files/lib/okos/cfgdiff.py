#!/usr/bin/env python

import argparse
import json
import sys
from cfgobjects import *
from okos_tools import *
import fcntl
import ubus

class OakmgrCfg(object):
    Templates = [
            #CfgKickoff(),
            CfgSystem(),
            CfgInterface(),
            CfgNetwork(),
            CfgPortForwarding(),
            CfgIpForwarding(),
            CfgMacIpBinding(),
            CfgDhcpOption(),
            CfgDone(),
            CfgSiteToSiteVPN(),
            CfgDDNS(),
            ]
    def __init__(self, f=''):
        super(OakmgrCfg, self).__init__()
        self.source = f
        self.objects = None
        try:
            with open(f, 'r') as cfg:
                fcntl.flock(cfg.fileno(), fcntl.LOCK_SH)
                j_str = cfg.read()
                self._json = json.loads(j_str, encoding='utf-8')
        except Exception as e:
            log_info("import json data failed!")
            self._json = {}


    def parse(self):
        self.objects = [self._json and t.parse(self._json) or [] for t in self.Templates]
        #return bool(len(self.Templates) == len(self.objects))
        return self

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
        log_debug('Configuration executed completedly...')
        return True

class ConfigEnv(object):
    def __init__(self):
        super(ConfigEnv, self).__init__()
    def __enter__(self):
        log_debug('\n\n\n>>>>>>>>>>>>>>  Configuration Executing <<<<<<<<<<<<<<<<')
        try:
            ubus.connect()
        except Exception, e:
            log_err("main ubus connect failed, {}".format(e))
        return self
    def __exit__(self, exception_type, value, traceback):
        try:
            ubus.disconnect()
        except Exception, e:
            log_err("main ubus disconnect failed, {}".format(e))

        if exception_type:
            log_err('configure failed with error %s :> %s <%s:%s>' % (exception_type, value, traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))
            return False
        
        log_debug('>>>>>>>>>>>>>>  Configuration Ended <<<<<<<<<<<<<<<<\n\n\n\n')
        return True

def config_exec(args):
    with ConfigEnv():
        with open(args.target, 'r') as ori:
            with open('/tmp/config.ori', 'w') as f:
                f.write(ori.read())
                f.write('\n')

        cur = OakmgrCfg(args.target).parse()
        ori = OakmgrCfg(args.original).parse()
        diff = cur - ori
        diff.dump()
        #return not diff.run() and 1 or 0
        if diff.run():
            return 0
        else:
            log_debug('>>>>>>>>>>>>>>  Configuration Failed <<<<<<<<<<<<<<<<\n\n\n\n')
            return 1

def main(args):
    log_debug(args)
    try:
        return config_exec(args)
    except Exception as e:
        log_err('Loading config with err %s' % (e))
        return 1



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create diff from current config to original one.')
    parser.add_argument('target', help='Current configuration file')
    parser.add_argument('-o', '--original', type=str, help='Original configuration file')
    #parser.add_argument('-f', '--file', type=str, help='configuration file')
    #parser.add_argument()
    args = parser.parse_args()

    sys.exit(main(args))


