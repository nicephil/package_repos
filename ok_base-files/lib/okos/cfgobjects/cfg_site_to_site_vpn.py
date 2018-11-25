#!/usr/bin/env python

from cfg_object import CfgObj, ConfigInputEnv, ConfigParseEnv, ConfigParaCheckEnv, ExceptionConfigParaError, ParameterChecker
from okos_tools import logcfg, logchecker
from constant import const

class CfgSiteToSiteVPN(CfgObj):
    differ = 'id'

    def __init__(self, entry=None):
        super(CfgSiteToSiteVPN, self).__init__()
        entry and self.data.update(entry)

    @classmethod
    @logcfg
    def parse(cls, j):
        vpns = j['network'].setdefault('site_to_site_vpns',[])
        with ConfigParseEnv(vpns, 'Site to Site VPN configuration', debug=True):
            res = [cls(vpn) for vpn in vpns]
        return res

    def _check_ikev_(self, input):
        input = input.lower()
        return bool(input in ('ikev1', 'ikev2')), input
    def _check_encryption_(self, input):
        input = input.lower()
        return bool(input in ('aes128', 'aes192', 'aes256', '3des')), input
    def _check_hash_(self, input):
        input = input.lower()
        return bool(input in ('sha1', 'md5')), input
    def _check_dh_(self, input):
        input = str(input).lower()
        return bool(input in ('2', '5', '14', '15', '16', '19', '20', '21', '25', '26',)), input

    @logcfg
    def add(self):
        new = self.data
        checker = ParameterChecker(new)
        with ConfigInputEnv(new, 'Create site to site vpn'):
            checker['id'] = (self._check_number_, None)
            checker['remote_ip'] = (self._check_ipaddr_, None)
            checker['local_ip'] = (self._check_ipaddr_, None)
            checker['pre_shared_key'] = (None, None)
            checker['remote_subnets'] = (None, None)
            checker['key_exchange_ver'] = (self._check_ikev_, 'ikev1')
            checker['encryption'] = (self._check_encryption_, 'aes128')
            checker['hash'] = (self._check_hash_, 'sha1')
            checker['dh_group'] = (self._check_dh_, 14)
            checker['perfect_forward_secrecy'] = (None, 1)
            checker['dynamic_routing'] = (None, 1)

        cmd = ['set_site2site_vpn.sh', 'set', checker['id'], '-S']
        cmd += ['--remote-subnets', checker['remote_subnets'], '--local', checker['local_ip'], '--remote', checker['remote_ip'], '--psk', checker['pre_shared_key']]
        cmd += ['--ikev', checker['key_exchange_ver'], '--encryption', checker['encryption'], '--hash', checker['hash'], '--dh', checker['dh_group']]
        cmd += checker['perfect_forward_secrecy'] and ['--pfs',] or []
        cmd += checker['dynamic_routing'] and ['--dynamic-routing', ] or []
        res = self.doit(cmd, 'set up site to siet vpn to %s' % (checker['remote_ip']))                
        return res

    @logcfg
    def remove(self):
        old = self.data
        checker = ParameterChecker(old)
        with ConfigInputEnv(old, 'Remove site to site vpn'):
            checker['id'] = (None, None)

        cmd = ['set_site2site_vpn.sh', 'del', checker['id'], '-S']
        res = self.doit(cmd, 'Site to site vpn %s Removed' % (checker['id']))                
        return res

    @logcfg
    def change(self):
        self.add()
        return True

    @classmethod
    @logcfg
    def post_run(cls):
        cls.doit(['/etc/init.d/ipsec', 'reload'], 'Restart ipsec')
        return True

