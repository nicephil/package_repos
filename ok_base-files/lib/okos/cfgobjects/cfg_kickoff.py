#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_tools import logcfg, logchecker
import json
from constant import const

class CfgKickoff(CfgObj):
    def __init__(self):
        super(CfgKickoff, self).__init__()

    @logcfg
    def parse(self, j):
        with open('/tmp/config.orgin', 'w+') as f:
            json.dump(j, f)
