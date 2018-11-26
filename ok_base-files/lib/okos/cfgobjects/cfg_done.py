#!/usr/bin/env python

from cfg_object import CfgObj
from okos_tools import logcfg
from constant import const

class CfgDone(CfgObj):
    def __init__(self):
        super(CfgDone, self).__init__()
    
    @classmethod
    @logcfg
    def parse(cls, j):
        pass

    @classmethod
    @logcfg
    def post_run(cls):
        cls.doit(['/etc/init.d/network', 'reload'], 'reload network', path='')
        cls.doit(['/etc/init.d/firewall', 'reload'], 'reload firewall', path='')
        cls.doit(['/etc/init.d/dnsmasq', 'reload'], 'reload dnsmasq', path='')
        return True

if __name__ == "__main__":
    pass