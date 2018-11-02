import Queue
import threading
import time, re
import okos_utils
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit, logit, ExecEnv, RepeatedTimer
import json
from constant import const
import vici
from collections import OrderedDict
import copy
import socket
import psutil
import time
import fcntl
import os, sys
import sqlite3
import netifaces as ni
import ubus
import ping_mgr

class IfStateEnv(ExecEnv):
    def __init__(self, desc):
        super(IfStateEnv, self).__init__('Interface State', desc=desc, raiseup=False)

class SystemEnv(ExecEnv):
    def __init__(self, desc):
        super(SystemEnv, self).__init__('System Infor', desc=desc, raiseup=False)

class DeviceInfoEnv(ExecEnv):
    def __init__(self, desc):
        super(DeviceInfoEnv, self).__init__('Device Infor', desc=desc, raiseup=False)

class SiteToSiteVpnInfoEnv(ExecEnv):
    def __init__(self, desc):
        super(SiteToSiteVpnInfoEnv, self).__init__('Site to Site VPN status', desc=desc, raiseup=False)

class IpsecViciEnv(ExecEnv):
    def __init__(self, desc):
        super(IpsecViciEnv, self).__init__('Site to Site VPN status', desc=desc, raiseup=False)
    def __enter__(self):
        return vici.Session()
        #return super(IpsecViciEnv, self).__enter__()

class StatusMgr(threading.Thread):
    def __init__(self, mailbox, conf_mgr):
        threading.Thread.__init__(self)
        self.name = 'StatusMgr'
        self.term = False
        self.conf_mgr = conf_mgr
        self.mailbox = mailbox
        self.timers = [
            RepeatedTimer('Site_VPN', 60, self.vpn_timer_func),
            RepeatedTimer('CPU_MEM_Status', 10, self.cpu_mem_timer_func),
            RepeatedTimer('IF_Status', 60, self.if_status_timer_func),
            RepeatedTimer('Device_Info', 60, self.collect_devinfo),
        ]
        
        '''
        try:
            self.sv = vici.Session()
        except Exception,e:
            log_warning("vici session init failed, {}".format(e))
        '''
        self.prev_conn_list = []
        self.prev_total_tx_bytes = 0
        self.prev_total_rx_bytes = 0
        self.ping_mgr = ping_mgr.PingMgr()
        self.ping_mgr.start()

    def run(self):
        for timer in self.timers:
            timer.start()
        while not self.term:
            time.sleep(60)

    def vpn_timer_func(self):
        sas = []
        with IpsecViciEnv('Query active VPN connections') as sw:
            sas = sw.list_sas()
            sas = [t_name for sa in sas for t_name,v in sa.iteritems() if v['state'] == 'ESTABLISHED' ]
            with open('/tmp/site_to_site_vpn.json', 'w+') as f:
                json.dump(sas, f)
        tunnels = []
        with SiteToSiteVpnInfoEnv('Prepare Site to Site VPN statues:'):
            vpn_conf = ubus.call('uci', 'get', {'config':'ipsec'})[0]['values']
            tunnels = [v for v in vpn_conf.itervalues() if v['.type'] == 'remote' ]
        statistic = {}
        vpn_sas = []
        with SiteToSiteVpnInfoEnv('Prepare Site to Site VPN statues:'):
            f = lambda i, sas: ('s_%s-t_%s' % (i,i) in sas) and 1 or 0
            vpn_sas = [{
                'id': t['vpnid'],
                'state': f(t['vpnid'], sas),
                'total_tx_bytes': 0,
                'total_rx_bytes': 0,
            } for t in tunnels]
            with open('/tmp/vpn_status.tmp','w+') as f:
                json.dump(vpn_sas,f)
            data = json.dumps({'list': vpn_sas})
        with SiteToSiteVpnInfoEnv('Report Site to Site VPN statues:'):
            msg = {
                'operate_type': const.VPN_CONN_STATUS_RESP_OPT_TYPE,
                'timestamp': int(time.time()),
                'cookie_id': 1,
                'data': data,
            }
            self.mailbox.pub(const.STATUS_Q, (1, msg), timeout=0)
            

    def cpu_mem_timer_func(self):
        with SystemEnv('Query cpu & memory information'):
            cpu_stats = psutil.cpu_percent(0)
            mem_stats = psutil.virtual_memory().percent
        with SystemEnv('Report cpu & memory information'):
            data_json = {
                'cpu_load': int(cpu_stats),
                'mem_load': int(mem_stats),
            }
            data = json.dumps(data_json)
            info_msg = {
                'operate_type': const.DEV_CPU_MEM_STATUS_RESP_OPT_TYPE,
                'timestamp': int(time.time()),
                'cookie_id': 0,
                'data': data,
            }
            self.mailbox.pub(const.STATUS_Q, (1, info_msg), timeout=0)

    def if_status_timer_func(self):
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
            devices = ubus.call('network.device','status', {})[0]
            #devices = {k:v for k,v in devices.iteritems() if k.startswith('eth')}
            devices = {k:v for k,v in devices.iteritems() if k in phy_ifnames}
            interfaces = {d: ubus.call('network.interface.' + phy_ifnames[d]['ifname'], 'status', {})[0] for d in devices}
            for ifx,c in devices.iteritems():
                c.update(interfaces[ifx])
            interfaces = devices
            network_conf = ubus.call('uci', 'get', {'config':'network'})[0]['values']
            network_conf = {cfg_ifnames[k]['phy']:v for k,v in network_conf.iteritems() if k in cfg_ifnames}
            dhcp_conf = ubus.call('uci', 'get', {'config':'dhcp'})[0]['values']
            dhcp_conf = {cfg_ifnames[k]['phy']:v for k,v in dhcp_conf.iteritems() if k in cfg_ifnames}

        ### interface status info
        #   |Name|Type|Description|
        #   |:--|:--|:--|
        #   |name|String||
        #   |ifname|String||
        #   |type|int|0 : WAN<br>1 : LAN<br>|
        #   |status|byte|0 : disabled<br>1 : enabled| ?
        #   |physical_state|byte|0 : down<br>1 : up|
        #   |state|byte|0 : disconnected<br>1 : connected|
        #   |bandwidth_config|int|0 : auto<br>10, 100, 1000| ?
        #   |duplex_config|byte|0 : auto<br>1 : full<br>2 : half| ?
        #   |bandwidth|int|10, 100, 1000(Mbps)|
        #   |duplex|byte|1 : full<br>2 : half|
        #   |ip_type|byte|0 : dhcp<br>1 : static<br>2 : pppoe|
        #   |ips|List|ip info|
        #   |gateway|String||
        #   |pppoe_username|String||
        #   |pppoe_password|String||
        #   |manual_dns|byte|0 : auto<br>1 : manual|?
        #   |dnss|String|such as "8.8.8.8,9.9.9.9"|
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
            ifx_input = interfaces[ifx_output['ifname']]
            if ifx_output['status']:
                ifx_output['dnss'] = ','.join([dns for dns in ifx_input['dns-server']])
                ifx_output['ips'] = [{'ip':ip['address'], 'netmask':ip['mask']} for ip in ifx_input['ipv4-address']]
                if ifx_output['type'] == const.DEV_CONF_PORT_TYPE['wan']:
                    defaultroutes = [r['nexthop'] for r in ifx_input['route'] if r['target'] == '0.0.0.0']
                    if defaultroutes:
                        ifx_output['gateway'] = defaultroutes[0]
        with IfStateEnv('IP Setting'):
            map(abstract_ip_setting, ifs_state)

        def abstract_pppoe(ifx_output):
            if ifx_output['type'] == const.DEV_CONF_PORT_TYPE['wan'] and ifx_output['proto'] == 'pppoe' and ifx_output['status']:
                ifx_input = network_conf[ifx_output['ifname']]
                ifx_output['pppoe_username'] = ifx_input['username']
                ifx_output['pppoe_password'] = ifx_input['password']
        with IfStateEnv('pppoe'):
            map(abstract_pppoe, ifs_state)

        def abstract_dhcp_server(ifx_output):
            if ifx_output['status'] and ifx_output['type'] == const.DEV_CONF_PORT_TYPE['lan']:
                ifx_input = dhcp_conf[ifx_output['ifname']]
                ifx_output['dhcp_start'] = ifx_input['start']
                ifx_output['dhcp_limit'] = ifx_input['limit']
        with IfStateEnv('DHCP server'):
            map(abstract_dhcp_server, ifs_state)


        with open('/tmp/if_state.tmp','w+') as f:
            json.dump(ifs_state,f)

        with IfStateEnv('Dump Interfaces State Data'):
            data = json.dumps({'list': ifs_state})

        with IfStateEnv('Post Interfaces State'):
            info_msg = {
                'operate_type': const.DEV_IF_STATUS_RESP_OPT_TYPE,
                'timestamp': int(time.time()),
                'cookie_id': 0,
                'data': data,
            }
            self.mailbox.pub(const.STATUS_Q, (1, info_msg), timeout=0)

    def collect_devinfo(self):
        with DeviceInfoEnv('Collect Device Infor'):
            data_json = {}
            productinfo_data = self.conf_mgr.get_productinfo_data()
            data_json['software_version'] = productinfo_data['swversion']
            data_json['boot_version'] = productinfo_data.setdefault('bootversion','v1.1.1')
            data_json['cpu'] = productinfo_data['cpu']
            data_json['memory'] = productinfo_data['mem']
            data_json['eth_port'] = productinfo_data['eth_port']
            data_json['sn'] = productinfo_data['serial']
            data_json['product_name'] = productinfo_data['model']

            confinfo_data = self.conf_mgr.get_confinfo_data()
            data_json['config_version'] = confinfo_data['config_version']

        with DeviceInfoEnv('Collect info from config_version_webui'):
            data_json['config_version_webui'] = ubus.call('uci', 'get', {"config":"system", "section":"@system[0]", "option":"config_version_webui"})[0]["value"]

        with DeviceInfoEnv('Report Device Info'):
            info_msg = {
                'operate_type': const.DEV_INFO_OPT_TYPE,
                'timestamp': int(time.time()),
                'cookie_id': 0,
                'data': json.dumps(data_json),
            }
            self.mailbox.pub(const.STATUS_Q, (200, info_msg), timeout=0)
        return info_msg

    def collect_total_bytes(self, new_conn_list):
        total_tx_bytes = 0
        total_rx_bytes = 0
        for k in self.prev_conn_list:
            i1 = -1
            for i1, k1 in enumerate(new_conn_list):
                if k['ike_id'] == k1['ike_id'] and k1['tx_bytes'] >= k['tx_bytes'] and k1['rx_bytes'] >= k['rx_bytes']:
                    break
            if i1 >= len(self.prev_conn_list)-1:
                total_tx_bytes = total_tx_bytes + k['tx_bytes']
                total_rx_bytes = total_rx_bytes + k['rx_bytes']
        for k in new_conn_list:
            total_tx_bytes = total_tx_bytes + k['tx_bytes']
            total_rx_bytes = total_rx_bytes + k['rx_bytes']
        msg = {}
        productinfo_data = self.conf_mgr.get_productinfo_data()
        msg['mac'] = productinfo_data['mac']
        msg['timestamp'] = int(time.time())
        data = {}
        msg['WLAN'] = data
        if total_tx_bytes >= self.prev_total_tx_bytes:
            data['Tx_Data_Bytes'] = total_tx_bytes - self.prev_total_tx_bytes
            self.prev_total_tx_bytes = total_tx_bytes
        else:
            data['Tx_Data_Bytes'] = 0
        if total_rx_bytes >= self.prev_total_rx_bytes:
            data['Rx_Data_Bytes'] = total_rx_bytes - self.prev_total_rx_bytes
            self.prev_total_rx_bytes = total_rx_bytes
        else:
            data['Rx_Data_Bytes'] = 0

        if data['Tx_Data_Bytes'] or data['Rx_Data_Bytes']:
            json_file = "apstats_{}_{}.json".format(productinfo_data['serial'],msg['timestamp'])
            capwapc_data = self.conf_mgr.get_capwapc()
            with open("/tmp/{}".format(json_file), "w+") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.truncate()
                f.write(json.dumps(msg))
                f.flush()
            files = {'{}'.format(json_file) : open('/tmp/{}'.format(json_file), 'r')}
            param_data = {
                'objectname':'{}'.format(json_file),
                'override':1
            }
            url="http://{mas_server}/nms/file/device/stat".format(mas_server=capwapc_data['mas_server'])
            okos_utils.post_url(url, param_data=param_data, files=files)
            os.system("cat /tmp/apstats_*.json|logger -t 'xxx';rm -rf /tmp/apstats_*.json")

    # sqlite3  $dbfile "BEGIN TRANSACTION;CREATE TABLE IF NOT EXISTS ${tablename}(PPPD_PID TEXT PRIMARY KEY NOT NULL,IFNAME,DEVICE,IPLOCAL,IPREMOTE,PEERNAME,TS,TX,RX,PEER_PUBIP);COMMIT;"
    # 16782|ppp0|/dev/pts/3|172.16.254.254|172.16.254.100|leilei.wang|1527671674|0|0|192.168.254.140
    def collect_conninfo_from_l2tp(self):
        conn_list = []
        sconn = None
        cur = None
        try:
            sconn = sqlite3.connect("/tmp/stationinfo.db")
            cur = sconn.cursor()
            cur.execute("select * from STAINFO")
            cur_list = cur.fetchall()
            #log_debug("cu.featchall:{}".format(cur_list))
            for v in cur_list:
                conns = dict()
                conns['state'] = 1
                conns['ike_id'] = -1
                conns['client_ip'] = v[9]
                conns['dynamic_ip'] = v[4]
                conns['username'] = v[5]
                conns['protocol'] = 'L2TP'
                conns['uptime'] = int(time.time()) - v[6]
                ifname = v[1]
                conns['tx_bytes'] = int(psutil.net_io_counters(pernic=True).get(ifname).bytes_recv)
                conns['rx_bytes'] = int(psutil.net_io_counters(pernic=True).get(ifname).bytes_sent)
                conn_list.append(conns)
        except Exception,e:
            log_warning('database err:{}'.format(e))
        finally:
            if cur:
                cur.close()
            if sconn:
                sconn.close()
        return conn_list

    def collect_vpn_conninfo(self):
        pass



    def collect_conninfo_from_ipsec(self):
        try:
            sas_list = self.vs.list_sas()
        except Exception, e:
            log_warning("list_sas:{}".format(e))
            try:
                self.vs = vici.Session()
            except Exception,e:
                log_warning("cannot recover vici")
            return None
        #log_debug("sas_list:")
        conn_list = []
        for k in sas_list:
            conns = dict()
            for k1, v1 in k.items():
                if v1['state'] != 'ESTABLISHED':
                    continue
                conns['state'] = 1
                conns['ike_id'] = v1['uniqueid']
                conns['client_ip'] = v1['remote-host']
                conns['uptime'] = v1['established']
                if 'remote-xauth-id' in v1:
                    conns['username'] = v1['remote-xauth-id']
                    conns['protocol'] = 'IPSec'
                if 'remote-vips' in v1:
                    conns['dynamic_ip'] = v1['remote-vips'][0]
                if 'remote-id' in v1:
                    conns['protocol'] = 'IKEv2'
                for k2, v2 in v1.items():
                    if k2 == "child-sas":
                        for k3, v3 in v2.items():
                            if 'bytes-in' in v3:
                                conns['tx_bytes'] = int(v3['bytes-in'])
                            if 'bytes-out' in v3:
                                conns['rx_bytes'] = int(v3['bytes-out'])
                            if 'name' in v3:
                                conns['username'] = v3['name']
                            if 'mode' in v3 and v3['mode'] != 'TRANSPORT':
                                conn_list.append(conns)
        return conn_list

    def collect_conninfo(self):
        msg = {}
        msg['operate_type'] = const.DEV_CONN_STATUS_RESP_OPT_TYPE
        msg['timestamp'] = int(time.time())
        msg['cookie_id'] = 1
        conn_list = []
        data_json = {}
        data_json['connections'] = conn_list
        cl1 = self.collect_conninfo_from_ipsec()
        if cl1:
            conn_list.extend(cl1)
        cl2 = self.collect_conninfo_from_l2tp()
        if cl2:
            conn_list.extend(cl2)
        #for i in conn_list:
            #log_debug("conn_list:{}".format(i))
        msg['data'] = json.dumps(data_json)

        self.collect_total_bytes(conn_list)

        self.prev_conn_list = copy.deepcopy(conn_list)
        return msg


    def collect_ddns_status(self):
        confinfo_data = self.conf_mgr.get_confinfo_data()
        json_data = {}
        msg = {}
        msg['operate_type'] = const.DEV_DDNS_STATUS_RESP_OPT_TYPE
        msg['timestamp'] = int(time.time())
        msg['cookie_id'] = 0
        json_data_list = {}
        json_data_list['ddnss'] = []
        for v in confinfo_data['network']['ddnss']:
            ddns_status = okos_utils.get_ddns_status(v['provider'])
            if not ddns_status:
                log_warning('ddclient start, but no ddclient cache')
                return None
            json_data['provider'] = v['provider']
            json_data['hostname'] = v['hostname']
            json_data['internal_ip'] = socket.gethostbyname(socket.gethostname())
            json_data['external_ip'] = ddns_status['ip'] if ddns_status['status'] else ''
            json_data['status'] = 0 if ddns_status['status'] == 'good' else 1
            json_data['updatetime'] = int(ddns_status['mtime']) if ddns_status['mtime'] else ddns_status['atime']
            json_data_list['ddnss'].append(json_data)
        msg['data'] = json.dumps(json_data_list)
        return msg

