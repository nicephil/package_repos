#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError
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
    def _check_entry_id_(self, entry_id, obj_name=''):
        p_id = const.FMT_PATTERN['port_fwd_id']
        return p_id.match(entry_id)
    @logchecker('Port Forwarding')
    def _check_ipaddr_(self, ipaddr, obj_name=''):
        p_ipaddr = const.FMT_PATTERN['ipaddr']
        return p_ipaddr.match(ipaddr)
    @logchecker('Port Forwarding')
    def _check_protocol_(self, protocol, obj_name=''):
        return protocol in ('udp', 'tcp', 'tcpudp')
    @logchecker('Port Forwarding')
    def _check_port_(self, port, obj_name=''):
        return True
    @logchecker('Port Forwarding')
    def _check_ifname_(self, ifname, obj_name=''):
        return True

    @logcfg
    def add(self):
        new = self.data
        with ConfigInputEnv(new, 'Port Forwarding configuration'):
            fmt = {'id':self._check_entry_id_, 
                    'interface_name':self._check_ifname_, 
                    'external_ip':self._check_ipaddr_,
                    'local_ip':self._check_ipaddr_, 
                    'protocol':self._check_protocol_, 
                    'external_port':self._check_port_, 
                    'local_port':self._check_port_,
                    }
            entry = {k:new[k] for k in fmt}
        
        for k, func in fmt.iteritems():
            res = func(entry[k], obj_name=k)
            if not res:
                return False
        cmd = [const.CONFIG_BIN_DIR+'set_port_forwarding.sh', entry['id'], ]
        cmd += ['--src-zone', 'UNTRUSTED', '--dst-zone', 'TRUSTED', ]
        cmd += ['--src-dip', entry['external_ip'], '--dst-ip', entry['local_ip'], '-p', entry['protocol'], ]
        cmd += ['--src-dport', entry['external_port'], '--dst-port', entry['local_port'], ]
        cmd += ['-S',]
        res = self.doit(cmd, 'Port Forwarding Setting')                
        return res
    @logcfg
    def remove(self):
        old = self.data
        with ConfigInputEnv(old, 'Port Forwarding configuration'):
            entry = {'id': old['id']}
        cmd = [const.CONFIG_BIN_DIR+'set_port_forwarding.sh', entry['id'], '-R', '-S']
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