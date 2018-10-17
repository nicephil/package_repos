#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_utils import logcfg, logchecker
#import ubus
from constant import const

class CfgPortForwarding(CfgObj):
    def __init__(self, entry={}):
        super(CfgPortForwarding, self).__init__()
        self.data.update(entry)
    
    @logcfg
    def parse(self, j):
        port_fwds = j['network'].setdefault('port_forwardings',[])
        with ConfigParseEnv(port_fwds, 'Port Forwarding configuration'):
            res = [CfgPortForwarding(p) for p in port_fwds]
        return res
    
    @logchecker('Port Forwarding')
    def _check_entry_id_(self, input, obj_name=''):
        p_id = const.FMT_PATTERN['port_fwd_id']
        return p_id.match(input), input
    @logchecker('Port Forwarding')
    def _check_ipaddr_(self, input, obj_name=''):
        p_ipaddr = const.FMT_PATTERN['ipaddr']
        return p_ipaddr.match(input), input
    @logchecker('Port Forwarding')
    def _check_protocol_(self, input, obj_name=''):
        return input in ('udp', 'tcp', 'tcpudp'), input
    @logchecker('Port Forwarding')
    def _check_port_(self, input, obj_name=''):
        p = const.FMT_PATTERN['p_socket_port_range']
        m = p.match(str(input))
        if not m:
            return False, 'Socket port range error'
        m = m.groups()
        start, end = int(m[0]), m[2] and int(m[2]) or m[2]
        if end is not None:
            if start >= 65536:
                return False, 'Socket port range error: port number must be less than 65536'
            if end <= start:
                return False, 'Socket port range error: end must be bigger than start'
        if start == 0:
            return False, 'Socket port range error: port number must be bigger than 0'
        return True, end and '%d:%d' % (start, end) or '%d' % (start)
    @logchecker('Port Forwarding')
    def _check_ifname_(self, input, obj_name=''):
        return True, input

    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'Port Forwarding configuration'):
            checker['id'] = (self._check_entry_id_, None)
            checker['interface_name'] = (self._check_ifname_, None)
            checker['external_ip'] = (self._check_ipaddr_, None)
            checker['local_ip'] = (self._check_ipaddr_, None)
            checker['protocol'] = (self._check_protocol_, None)
            checker['external_port'] = (self._check_port_, None)
            checker['local_port'] = (self._check_port_, None)
            if not checker.dump():
                return False

        cmd = [const.CONFIG_BIN_DIR+'set_port_forwarding.sh', checker['id'], ]
        cmd += ['--src-zone', 'UNTRUSTED', '--dst-zone', 'TRUSTED', ]
        cmd += ['--src-dip', checker['external_ip'], '--dst-ip', checker['local_ip'], '-p', checker['protocol'], ]
        cmd += ['--src-dport', checker['external_port'], '--dst-port', checker['local_port'], ]
        cmd += ['-S',]
        res = self.doit(cmd, 'Port Forwarding Setting')                
        return res
    @logcfg
    def remove(self):
        old = self.data
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'Port Forwarding configuration'):
            checker['id'] = (self._check_entry_id_, None)
            if not checker.dump():
                return False
        cmd = [const.CONFIG_BIN_DIR+'set_port_forwarding.sh', checker['id'], '-R', '-S']
        res = self.doit(cmd, 'Port Forwarding Entry Removed')                
        return res
    @logcfg
    def change(self):
        self.add()
        return True

    @logcfg
    def post_run(self):
        self.doit(['/etc/init.d/firewall', 'reload'], 'Restart firewall')
        return True