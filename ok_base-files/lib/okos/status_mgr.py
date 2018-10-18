import Queue
import threading
import time, re
import okos_utils
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit, logit, ExecEnv
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


class StatusMgr(threading.Thread):
    def __init__(self, mailbox, conf_mgr):
        threading.Thread.__init__(self)
        self.name = 'StatusMgr'
        self.term = False
        self.conf_mgr = conf_mgr
        self.mailbox = mailbox
        try:
            self.sv = vici.Session()
        except Exception,e:
            log_warning("vici session init failed, {}".format(e))
        self.prev_conn_list = []
        self.cpu_mem_timer = threading.Timer(1, self.cpu_mem_timer_func)
        self.cpu_mem_timer.name = 'CPU_MEM_Status'
        self.cpu_mem_timer.start()
        self.if_status_timer = threading.Timer(1, self.if_status_timer_func)
        self.if_status_timer.name = 'IF_Status'
        self.if_status_timer.start()
        self.prev_total_tx_bytes = 0
        self.prev_total_rx_bytes = 0
        self.ping_mgr = ping_mgr.PingMgr()
        self.ping_mgr.start()

    def cpu_mem_timer_func(self):
        try:
            cpu_stats = psutil.cpu_percent(0)
            mem_stats = psutil.virtual_memory().percent
            info_msg = {}
            info_msg['operate_type'] = const.DEV_CPU_MEM_STATUS_RESP_OPT_TYPE
            info_msg['timestamp'] = int(time.time())
            info_msg['cookie_id'] = 0
            data_json = {}
            data_json['cpu_load'] = int(cpu_stats)
            data_json['mem_load'] = int(mem_stats)
            info_msg['data'] = json.dumps(data_json)
            self.mailbox.pub(const.STATUS_Q, (1, info_msg), timeout=0)
        except Exception, e:
            log_warning("cpu_mem_status:{}".format(e))

        self.cpu_mem_timer = threading.Timer(5, self.cpu_mem_timer_func)
        self.cpu_mem_timer.name = 'CPU_MEM_Status'
        self.cpu_mem_timer.start()

    @logit
    def if_status_timer_func(self):
        '''
        This timer will be self-kicked off for every 60 seconds.
        '''
        phy_ifnames = const.PORT_MAPPING_PHY
        cfg_ifnames = const.PORT_MAPPING_CONFIG

        with IfStateEnv('Aquire State and Config from ubus'):
            # {'eth0':...}
            devices = ubus.call('network.device','status', {})[0]
            #devices = {k:v for k,v in devices.iteritems() if k.startswith('eth')}
            devices = {k:v for k,v in devices.iteritems() if k in phy_ifnames}
            interfaces = {d: ubus.call('network.interface.' + phy_ifnames[d]['ifname'], 'status', {})[0] for d in devices}
            for ifx,c in interfaces.iteritems():
                c.update(devices[ifx])
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
            ifs_state = {ifname: {
                    'ifname': ifname,
                    'name': phy_ifnames[ifname]['logic'],
                    'type': phy_ifnames[ifname]['type'],
                    #'mac': data['macaddr'],
                } for ifname in phy_ifnames
            }

        def update_ifs_state(ifs_next):
            for ifname, ifx in ifs_state.iteritems():
                if ifname in ifs_next:
                    ifx.update(ifs_next[ifname])

        def abstract_link_status(ifx_output, ifx_input):
            ifx_output['state'] = ifx_input['up'] and 1 or 0
            ifx_output['physical_state'] = ifx_input.setdefault('carrier', False) and 1 or 0
            ifx_output['proto'] = ifx_input.setdefault('proto','none')
            ifx_output['status'] = ifx_output['proto'] != 'none' and 1 or 0
            ifx_output['ip_type'] = ip_types.setdefault(ifx_output['proto'], -1)

        with IfStateEnv('Link Statue'):
            update_ifs_state({ifname: {
                'state': data['up'] and 1 or 0,
                'physical_state': data.setdefault('carrier', False) and 1 or 0,
                'proto': data.setdefault('proto','none'),
                } for ifname, data in interfaces.iteritems()
            })

        with IfStateEnv('IP protocol'):
            update_ifs_state({ifname: {
                    'status': data['proto'] != 'none' and 1 or 0,
                    'ip_type': ip_types.setdefault(data['proto'], -1),
                } for ifname, data in interfaces.iteritems()
            })

        p = re.compile('^([0-9]+)([FH])$')
        def abstract_speed(ifx_output, ifx_input):
            if 'speed' in ifx_input and ifx_output['physical_state']:
                speed = ifx_input['speed']
                res = p.match(speed)
                if res:
                    res = res.groups()
                    ifx_output['bandwidth'] = res[0]
                    ifx_output['duplex'] = res[1] == 'F' and 1 or 2
            return ifx_output
        map(abstract_speed, ifs_state, interfaces)


        with IfStateEnv('Interface speed'):

            speeds = { ifname: ('speed' in data and ifs_state[ifname]['physical_state']) and data['speed'] or '' for ifname, data in interfaces.iteritems()}
            report = {}
            for ifname in interfaces:
                res = p.match(speeds[ifname])
                res = res and res.groups()
                report[ifname] = res and {'bandwidth':res[0], 'duplex':res[1] == 'F' and 1 or 2} or {}
            update_ifs_state(report)

        with IfStateEnv('IP address'):
            update_ifs_state({ifname: {
                    'uptime': data['uptime'],
                    'dnss': ','.join([dns for dns in data['dns-server']]),
                    'ips': [
                            {'ip': ipv4_addr['address'],
                            'netmask': ipv4_addr['mask'],
                        } for ipv4_addr in data['ipv4-address']
                    ],
                } for ifname, data in interfaces.iteritems()
                    if ifs_state[ifname]['status']
            })
        with IfStateEnv('Gateway'):
            gateways = {ifname: [r['nexthop'] for r in data['route'] if r['target'] == '0.0.0.0']
                        for ifname, data in interfaces.iteritems()
                            if ifs_state[ifx]['state'] and
                                ifs_state[ifx]['type'] == const.DEV_CONF_PORT_TYPE['wan']
                    }
            update_ifs_state({ifname: { 'gateway': data[0]}
                for ifname, data in gateways.iteritems() if data
            })

        with IfStateEnv('pppoe'):
            update_ifs_state({ifx: {
                    'pppoe_username': network_conf[ifs_state[ifx]['ifname']]['username'],
                    'pppoe_password': network_conf[ifs_state[ifx]['ifname']]['password'],
                } for ifx, v in interfaces.iteritems()
                    if ifs_state[ifx]['type'] == const.DEV_CONF_PORT_TYPE['wan'] and
                        ifs_state[ifx]['proto'] == 'pppoe' and
                        ifs_state[ifx]['status']
            })
        with IfStateEnv('DHCP server'):
            update_ifs_state({ifx: {
                    'dhcp_start': dhcp_conf[ifx]['start'],
                    'dhcp_limit': dhcp_conf[ifx]['limit'],
                } for ifx, v in interfaces.iteritems()
                    if ifs_state[ifx]['status'] and
                        ifs_state[ifx]['type'] == const.DEV_CONF_PORT_TYPE['lan']
            })

        info_msg = {
            'operate_type': const.DEV_IF_STATUS_RESP_OPT_TYPE,
            'timestamp': int(time.time()),
            'cookie_id': 0,
            'data': json.dumps({'list':[v for k,v in ifs_state.iteritems()]}),
        }
        with open('/tmp/if_state.tmp','w+') as f:
            json.dump(ifs_state,f)

        self.mailbox.pub(const.STATUS_Q, (1, info_msg), timeout=0)

        self.if_status_timer = threading.Timer(60, self.if_status_timer_func)
        self.if_status_timer.name = 'IF_Status'
        self.if_status_timer.start()
        return info_msg

    def run(self):
        self.process_data()

    def collect_devinfo(self):
        info_msg = {}
        info_msg['operate_type'] = const.DEV_INFO_OPT_TYPE
        info_msg['timestamp'] = int(time.time())
        info_msg['cookie_id'] = 0
        data_json = {}
        productinfo_data = self.conf_mgr.get_productinfo_data()
        data_json['software_version'] = productinfo_data['swversion']
        data_json['boot_version'] = productinfo_data['bootversion'] if 'bootversion' in productinfo_data else 'v1.1.1'
        data_json['cpu'] = productinfo_data['cpu']
        data_json['memory'] = productinfo_data['mem']
        data_json['eth_port'] = productinfo_data['eth_port']
        data_json['sn'] = productinfo_data['serial']
        data_json['product_name'] = productinfo_data['model']
        if 'port_status' in productinfo_data:
            data_json['port_status'] = productinfo_data['port_status']
        data_json['uptime'] = int(round(time.time() - psutil.BOOT_TIME))
        try:
            data_json['internal_ip'] = ni.ifaddresses(productinfo_data['eth_port'])[ni.AF_INET][0]['addr']
        except:
            data_json['internal_ip'] = ni.ifaddresses('pppoe-wan')[ni.AF_INET][0]['addr']

        confinfo_data = self.conf_mgr.get_confinfo_data()
        data_json['config_version'] = confinfo_data['config_version']
        try:
            data_json['config_version_webui'] = ubus.call('uci', 'get', {"config":"system", "section":"@system[0]", "option":"config_version_webui"})[0]["value"]
        except Exception, e:
            log_err("config_version_webui not found {}".format(e))
        info_msg['data'] = json.dumps(data_json)
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

    def process_data(self):
        i = 0
        while not self.term:
            if i >= 2:
                i = 0
                msg = self.collect_conninfo()
                self.mailbox.pub(const.STATUS_Q, (1, msg), timeout=0)
                msg = self.collect_devinfo()
                self.mailbox.pub(const.STATUS_Q, (200, msg), timeout=0)
            try:
                msg = self.collect_ddns_status()
            except Exception, e:
                log_warning("collect_ddns_staus:{}".format(e))
                msg = None
            self.mailbox.pub(const.STATUS_Q, (200, msg), timeout=0)
            i  = i + 1
            time.sleep(5)
