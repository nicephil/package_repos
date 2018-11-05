#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_utils import logcfg, logchecker
#import ubus
from constant import const

class CfgDone(CfgObj):
    def __init__(self):
        super(CfgDone, self).__init__()

    @logcfg
    def post_run(self):
        self.doit(['/etc/init.d/dnsmasq', 'reload'], 'Restart dnsmasq', path='')
        self.doit(['/etc/init.d/network', 'reload'], 'Restart network', path='')
        self.doit(['/etc/init.d/firewall', 'reload'], 'Restart firewall', path='')
        return True