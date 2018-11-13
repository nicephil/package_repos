
from okos_tools import *
from constant import const
import vici
import os
import subprocess
import re


class IpsecViciEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(IpsecViciEnv, self).__init__('Site to Site VPN status', desc=desc, raiseup=False, debug=debug)
    def __enter__(self):
        return vici.Session()
        #return super(IpsecViciEnv, self).__enter__()

class SiteToSiteVpnInfoEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(SiteToSiteVpnInfoEnv, self).__init__('Site to Site VPN status', desc=desc, raiseup=False, debug=debug)


class Site2SiteVpnReporter(Poster):
    def __init__(self, mailbox, operate_type=const.VPN_CONN_STATUS_RESP_OPT_TYPE, name='Site2SiteVpnTimer', interval=60, debug=False):
        super(Site2SiteVpnReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug)
        self.debug = debug
    def handler(self, *args, **kwargs):
        sas = []
        with IpsecViciEnv('Query active VPN connections', debug=self.debug) as sw:
            sas = sw.list_sas()
            sas = [t_name for sa in sas for t_name,v in sa.iteritems() if v['state'] == 'ESTABLISHED' ]
            #with open('/tmp/site_to_site_vpn.json', 'w+') as f:
            #    json.dump(sas, f)
        tunnels = []
        with SiteToSiteVpnInfoEnv('Query Site to Site VPN config:', debug=self.debug):
            vpn_conf = UciConfig('ipsec')
            tunnels = [v for _,v in vpn_conf.iteritems() if v.type == 'remote']
            #vpn_conf = ubus.call('uci', 'get', {'config':'ipsec'})[0]['values']
            #tunnels = [v for v in vpn_conf.itervalues() if v['.type'] == 'remote' ]
        statistic = []
        with SiteToSiteVpnInfoEnv('Prepare Site to Site VPN statistic:', debug=self.debug):
            with open(os.devnull, 'w') as DEVNULL:
                stats = [subprocess.check_output([const.CONFIG_BIN_DIR+'set_site2site_vpn.sh', 'statistic', t['vpnid']], stderr=DEVNULL) for t in tunnels]
            def split_data(stat):
                p = re.compile('^RX:([0-9]*)[ ]+TX:([0-9]*)')
                if stat:
                    m = p.match(stat)
                    if m:
                        return m.groups()
                return ('0','0')
            statistic = map(split_data, stats)
        vpn_sas = []
        with SiteToSiteVpnInfoEnv('Prepare Site to Site VPN statues:', debug=self.debug):
            f = lambda i, sas: ('s_%s-t_%s' % (i,i) in sas) and 1 or 0
            vpn_sas = [{
                'id': t['vpnid'],
                'state': f(t['vpnid'], sas),
                'total_tx_bytes': statistic[i][1],
                'total_rx_bytes': statistic[i][0],
            } for i,t in enumerate(tunnels)]
            #with open('/tmp/vpn_status.tmp','w+') as f:
            #    json.dump(vpn_sas,f)
        return vpn_sas and {'site_to_site_vpns': vpn_sas} or None
