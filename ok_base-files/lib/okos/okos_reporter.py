from okos_tools import ExecEnv, SystemCall
import vici
from okos_tools import Poster, Timer
from constant import const
from okos_tools import log_debug, log_info
from okos_tools import UciConfig, UciSection, UciStatus, PRODUCT_INFO, CAPWAP_SERVER
import os
import subprocess
import re
import psutil
from okos_tools import get_whole_confinfo, post_url
import netifaces as ni
import time
import md5


class IfStateEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(IfStateEnv, self).__init__('Interface State', desc=desc, raiseup=False, debug=debug)

class SystemEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(SystemEnv, self).__init__('System Infor', desc=desc, raiseup=False, debug=debug)

class DeviceInfoEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(DeviceInfoEnv, self).__init__('Device Infor', desc=desc, raiseup=False, debug=debug)

class SiteToSiteVpnInfoEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(SiteToSiteVpnInfoEnv, self).__init__('Site to Site VPN status', desc=desc, raiseup=False, debug=debug)

class IpsecViciEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(IpsecViciEnv, self).__init__('Site to Site VPN status', desc=desc, raiseup=False, debug=debug)
    def __enter__(self):
        return vici.Session()
        #return super(IpsecViciEnv, self).__enter__()


class WiredClientReporter(Poster):
    def __init__(self, mailbox, operate_type=const.CLIENT_ONLINE_STATUS_RESP_OPT_TYPE, name='WiredClientTimer', interval=60):
        super(WiredClientReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True)
    def handler(self, *args, **kwargs):
        arpt = SystemCall().get_arp_entries()
        arpt = [{'mac': a['HW address'], 'ip': a['IP address']} for a in arpt]
        return {'clients': arpt}


class SystemHealthReporter(Poster):
    def __init__(self, mailbox, operate_type=const.DEV_CPU_MEM_STATUS_RESP_OPT_TYPE, name='CpuMemTimer', interval=10):
        super(SystemHealthReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True, pri=1)
    def handler(self, *args, **kwargs):
        with SystemEnv('Query cpu & memory information'):
            cpu_stats = psutil.cpu_percent(0)
            mem_stats = psutil.virtual_memory().percent
        data_json = {}
        with SystemEnv('Report cpu & memory information'):
            data_json['cpu_load'] = int(cpu_stats)
            data_json['mem_load'] = int(mem_stats)
        return data_json

class Site2SiteVpnReporter(Poster):
    def __init__(self, mailbox, operate_type=const.VPN_CONN_STATUS_RESP_OPT_TYPE, name='Site2SiteVpnTimer', interval=60):
        super(Site2SiteVpnReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True)
    def handler(self, *args, **kwargs):
        sas = []
        with IpsecViciEnv('Query active VPN connections') as sw:
            sas = sw.list_sas()
            sas = [t_name for sa in sas for t_name,v in sa.iteritems() if v['state'] == 'ESTABLISHED' ]
            #with open('/tmp/site_to_site_vpn.json', 'w+') as f:
            #    json.dump(sas, f)
        tunnels = []
        with SiteToSiteVpnInfoEnv('Query Site to Site VPN config:'):
            vpn_conf = UciConfig('ipsec')
            tunnels = [v for _,v in vpn_conf.iteritems() if v.type == 'remote']
            #vpn_conf = ubus.call('uci', 'get', {'config':'ipsec'})[0]['values']
            #tunnels = [v for v in vpn_conf.itervalues() if v['.type'] == 'remote' ]
        statistic = []
        with SiteToSiteVpnInfoEnv('Prepare Site to Site VPN statistic:'):
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
        with SiteToSiteVpnInfoEnv('Prepare Site to Site VPN statues:'):
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

class IfStatusReporter(Poster):
    def __init__(self, mailbox, operate_type=const.DEV_IF_STATUS_RESP_OPT_TYPE, name='IfStatusTimer', interval=5):
        super(IfStatusReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True)
    def handler(self, *args, **kwargs):
        '''
        This timer will be self-kicked off for every 60 seconds.
        '''
        phy_ifnames = const.PORT_MAPPING_PHY
        cfg_ifnames = const.PORT_MAPPING_CONFIG

        '''
                    |  WAN   |  WAN1  |  WAN2  | LAN4053
        config: ----+--------+--------+--------+---------
        enable      |   y    |   n    |   n    |   y
        cable       |   on   |  off   |  off   |  off
        device: ----+--------+--------+--------+---------
        up          |   y    |   y    |   y    |   y
        carrier     |   y    |   n    |   n    |   n     # physical state
        speed       | 1000F  |  -1F   |  -1F   |  -1F
        mtu         |  1492  |  1500  |  1500  |  1500
        mac addr    |        |        |        |
        interface: -+--------+--------+--------+---------
        up          |   y    |   n    |   n    |   y     # Admin state
        pending     |   n    |   n    |   n    |   n
        available   |   y    |   y    |   y    |   y
        dynamic     |   n    |   n    |   n    |   n
        uptime      |  3705  |   -    |   -    |  4036
        l3_device   |  eth0  |   -    |   -    |  eth3
        device      |  eth0  |  eth1  |  eth2  |  eth3
        proto       | static |  none  |  none  | static
        ip addresses|   y    |   -    |   -    |   y
        dnss        |   y    |   -    |   -    |   y
        routes      |   y    |   -    |   -    |   y
        '''
        with IfStateEnv('Aquire State and Config from ubus'):
            # {'eth0':...}
            #devices = ubus.call('network.device','status', {})[0]
            #devices = {k:v for k,v in devices.iteritems() if k.startswith('eth')}
            devices = {k:v for k,v in UciStatus('network.device').iteritems() if k in phy_ifnames}
            #interfaces = {d: ubus.call('network.interface.' + phy_ifnames[d]['ifname'], 'status', {})[0] for d in devices}
            interfaces = {d: UciStatus('network.interface.' + phy_ifnames[d]['ifname']).dump() for d in devices}
            for ifx,c in devices.iteritems():
                c.update(interfaces[ifx])
            interfaces = devices
            #network_conf = ubus.call('uci', 'get', {'config':'network'})[0]['values']
            network_conf = UciConfig('network')
            network_conf = {cfg_ifnames[k]['phy']:v for k,v in network_conf.iteritems() if k in cfg_ifnames}
            #dhcp_conf = ubus.call('uci', 'get', {'config':'dhcp'})[0]['values']
            dhcp_conf = UciConfig('dhcp')
            dhcp_conf = {cfg_ifnames[k]['phy']:v for k,v in dhcp_conf.iteritems() if k in cfg_ifnames}

        ip_types = {'dhcp': 0, 'static':1, 'pppoe': 2}
        with IfStateEnv('Create Basic interfaces infor'):
            ifs_state = [{
                    'ifname': ifname,
                    'name': phy_ifnames[ifname]['logic'],
                    'type': phy_ifnames[ifname]['type'],
                    #'mac': data['macaddr'],
            } for ifname in phy_ifnames]

        def update_ifs_state(ifs_next):
            for ifname, ifx in ifs_state.iteritems():
                if ifname in ifs_next:
                    ifx.update(ifs_next[ifname])

        def abstract_link_status(ifx_output):
            ifx_input = interfaces[ifx_output['ifname']]
            ifx_output['state'] = ifx_output['physical_state'] = ifx_input.setdefault('carrier', False) and 1 or 0
            ifx_output['proto'] = ifx_input.setdefault('proto','none')
            ifx_output['status'] = ifx_output['proto'] != 'none' and 1 or 0 # It's admin state
            ifx_output['ip_type'] = ip_types.setdefault(ifx_output['proto'], -1)
        with IfStateEnv('Link Statue'):
            map(abstract_link_status, ifs_state)

        p = re.compile('^([0-9]+)([FH])$')
        def abstract_speed(ifx_output):
            ifx_input = interfaces[ifx_output['ifname']]
            if ifx_output['status'] and 'uptime' in ifx_input:
                ifx_output['uptime'] = ifx_input['uptime']
            if ifx_output['physical_state'] and 'speed' in ifx_input:
                res = p.match(ifx_input['speed'])
                if res:
                    bandwidth, duplex = res.groups()
                    ifx_output['bandwidth'] = bandwidth
                    ifx_output['duplex'] = duplex == 'F' and 1 or 2
        with IfStateEnv('Interface speed'):
            map(abstract_speed, ifs_state)

        def abstract_ip_setting(ifx_output):
            ifname = ifx_output['ifname']
            with IfStateEnv('IP Setting on %s' % (ifname)):
                ifx_input = interfaces[ifname]
                if ifx_output['status']:
                    ifx_output['dnss'] = ','.join([dns for dns in ifx_input.setdefault('dns-server', [])])
                    ifx_output['ips'] = [{'ip':ip['address'], 'netmask':ip['mask']} for ip in ifx_input.setdefault('ipv4-address',[])]
                    if ifx_output['type'] == const.DEV_CONF_PORT_TYPE['wan']:
                        defaultroutes = [r['nexthop'] for r in ifx_input.setdefault('route',[]) if r['target'] == '0.0.0.0']
                        if defaultroutes:
                            ifx_output['gateway'] = defaultroutes[0]
        map(abstract_ip_setting, ifs_state)

        def abstract_pppoe(ifx_output):
            ifname = ifx_output['ifname']
            with IfStateEnv('pppoe on %s' % (ifname)):
                if ifx_output['type'] == const.DEV_CONF_PORT_TYPE['wan'] and ifx_output['proto'] == 'pppoe' and ifx_output['status']:
                    ifx_input = network_conf[ifname]
                    ifx_output['pppoe_username'] = ifx_input['username']
                    ifx_output['pppoe_password'] = ifx_input['password']
        map(abstract_pppoe, ifs_state)

        def abstract_dhcp_server(ifx_output):
            ifname = ifx_output['ifname']
            with IfStateEnv('DHCP server on %s' % (ifname)):
                if ifx_output['status'] and ifx_output['type'] == const.DEV_CONF_PORT_TYPE['lan']:
                    ifx_input = dhcp_conf[ifname]
                    ifx_output['dhcp_start'] = ifx_input['start']
                    ifx_output['dhcp_limit'] = ifx_input['limit']
        map(abstract_dhcp_server, ifs_state)


        #with open('/tmp/if_state.tmp','w+') as f:
        #    json.dump(ifs_state,f)

        return {'list': ifs_state}


class DeviceReporter(Poster):
    def __init__(self, mailbox, operate_type=const.DEV_INFO_OPT_TYPE, name='DeviceInfoTimer', interval=60):
        super(DeviceReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True)
        self.productinfo_data = PRODUCT_INFO.renew()
        self.capwap_server = CAPWAP_SERVER.renew()
    def handler(self, *args, **kwargs):
        with DeviceInfoEnv('Collect Device Infor'):
            data_json = {}
            productinfo_data = self.productinfo_data
            data_json['software_version'] = productinfo_data['swversion']
            data_json['boot_version'] = productinfo_data['bootversion'] or 'v1.1.1'
            data_json['cpu'] = productinfo_data['cpu']
            data_json['memory'] = productinfo_data['mem']
            data_json['eth_port'] = productinfo_data['eth_port']
            data_json['sn'] = productinfo_data['serial']
            data_json['product_name'] = productinfo_data['model']

            confinfo_data = get_whole_confinfo()
            data_json['config_version'] = confinfo_data['config_version']

        with DeviceInfoEnv('Collect info for config_version_webui'):
            #data_json['config_version_webui'] = ubus.call('uci', 'get', {"config":"system", "section":"@system[0]", "option":"config_version_webui"})[0]["value"]
            data_json['config_version_webui'] = UciSection('system', 'system')['config_version_webui']
        with DeviceInfoEnv('Collect info for local ip address'):
            #mas_server = ubus.call('uci', 'get', {'config':'capwapc', 'section':'server'})[0]['values'].setdefault('mas_server', '')
            mas_server = self.capwap_server['mas_server']
            _, _, data_json['internal_ip'] = SystemCall(debug=False).localip2target(mas_server)

        return data_json

class Redirector(Timer):
    def __init__(self, name='Redirector', interval=120):
        super(Redirector, self).__init__(name, interval, repeated=True)
        self.product_info = PRODUCT_INFO.renew()
        self.capwap_server = CAPWAP_SERVER.renew()
    def handler(self, *args, **kwargs):
        post_data = {}
        post_data['version'] = self.product_info['swversion']
        post_data['device'] = self.product_info['mac']
        post_data['device_type'] = self.product_info['production']
        post_data['manufacturer'] = self.product_info['model']
        post_data['sn'] = self.product_info['serial']
        try:
            post_data['private_ip'] = ni.ifaddresses(self.product_info['eth_port'])[ni.AF_INET][0]['addr']
            post_data['private_mask'] = ni.ifaddresses(self.product_info['eth_port'])[ni.AF_INET][0]['netmask']
        except Exception, e:
            try:
                post_data['private_ip'] = ni.ifaddresses('pppoe-wan')[ni.AF_INET][0]['addr']
                post_data['private_mask'] = ni.ifaddresses('pppoe-wan')[ni.AF_INET][0]['netmask']
            except Exception, e:
                log_info("can not get private_ip to query redirector, err:{}".format(e))

        key = md5.new("{SALT}{_mac}".format(SALT=const.SALT, _mac=post_data['device'])).hexdigest()
        url="http://{_server_ip}:{PORT}/redirector/v1/device/register/?key={KEY}".format(_server_ip=const.DEFAULT_ADDR,
                                                                                            PORT=const.DEFAULT_PORT,
                                                                                            KEY=key)
        request_data = post_url(url, json_data=post_data)
        '''
        print request_data
        import random
        if random.randint(1,100) % 2:
            request_data['oakmgr_pub_name'] = 'xxia.hz.oakridge.io'
        '''
        # 2. update the new capwapc fetched from redirector
        if request_data and 'oakmgr_pub_name' in request_data:
            if request_data['oakmgr_pub_name'] != self.capwap_server['mas_server']:
                self.capwap_server['mas_server'] = request_data['oakmgr_pub_name']
                self.capwap_server.commit()
