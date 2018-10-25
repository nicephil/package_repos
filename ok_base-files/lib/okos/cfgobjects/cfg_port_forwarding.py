#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_utils import logcfg, logchecker
#import ubus
from constant import const

class ExceptionConfigPortfwdParaError(ExceptionConfigParaError):
    def __init__(self, param, reason, data=None):
        super(ExceptionConfigPortfwdParaError, self).__init__('Port Forwarding', param, reason, data)
class ExceptionConfigPortfwdParaPortError(ExceptionConfigPortfwdParaError):
    def __init__(self, param, reason, data=None):
        super(ExceptionConfigPortfwdParaPortError, self).__init__('socket port', reason, data)

class CfgPortForwarding(CfgObj):
    def __init__(self, entry={}):
        super(CfgPortForwarding, self).__init__(differ='id')
        self.data.update(entry)
        if entry:
            self.data['id'] += '_port'
    
    @logcfg
    def parse(self, j):
        port_fwds = j['network'].setdefault('port_forwardings',[])
        with ConfigParseEnv(port_fwds, 'Port Forwarding configuration'):
            res = [CfgPortForwarding(p) for p in port_fwds]
        return res
    
    def _check_protocol_(self, input):
        return input in ('udp', 'tcp', 'tcpudp'), input

    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'Port Forwarding configuration'):
            checker['id'] = (None, None)
            checker['interface_name'] = (None, None)
            checker['external_ip'] = (self._check_ipaddr_, None)
            checker['local_ip'] = (self._check_ipaddr_, None)
            checker['protocol'] = (self._check_protocol_, None)
            checker['external_port'] = (self._check_sock_port_, None)
            checker['local_port'] = (self._check_sock_port_, None)

        cmd = [const.CONFIG_BIN_DIR+'set_port_forwarding.sh', checker['id'], '-S', ]
        cmd += ['--src-zone', 'UNTRUSTED', '--dst-zone', 'TRUSTED', ]
        cmd += ['--src-dip', checker['external_ip'], '--dst-ip', checker['local_ip'], '--proto', checker['protocol'], ]
        cmd += ['--src-dport', checker['external_port'], '--dst-port', checker['local_port'], ]
        res = self.doit(cmd, 'Port Forwarding Setting')                
        return res
    @logcfg
    def remove(self):
        old = self.data
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'Port Forwarding removement'):
            checker['id'] = (None, None)
        cmd = [const.CONFIG_BIN_DIR+'set_port_forwarding.sh', checker['id'], '-R', '-S']
        res = self.doit(cmd, 'Port Forwarding Entry Removed')                
        return res
    @logcfg
    def change(self):
        self.add()
        return True

