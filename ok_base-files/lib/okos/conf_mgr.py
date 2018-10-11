import Queue
import threading
import time
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit
import okos_utils
import json
from constant import const
import vici
import os
import ubus
import subprocess
from datetime import datetime
from signal import SIGKILL

class ConfMgr(threading.Thread):
    def __init__(self, mailbox):
        threading.Thread.__init__(self)
        self.name = 'ConfMgr'
        self.mailbox = mailbox
        self.term = False
        try:
            self.sv = vici.Session()
        except Exception,e:
            log_warning("vici session init failed, {}".format(e))
        self.productinfo_data = okos_utils.get_productinfo()
        self.confinfo_data = okos_utils.get_whole_confinfo()
        self.capwapc_data = okos_utils.get_capwapc()
        self.handlers = {}
        self.register_handlers()

    def register_handlers(self):
        # conf_request
        self.handlers[const.DEV_CONF_OPT_TYPE] = {}
        self.handlers[const.DEV_CONF_OPT_TYPE]['request_handler'] = self.handle_conf
        self.handlers[const.DEV_CONF_OPT_TYPE]['response_handler'] = self.conf_response
        self.handlers[const.DEV_CONF_OPT_TYPE]['response_id'] = const.DEV_CONF_RESP_OPT_TYPE

        # webui conf_query
        self.handlers[const.DEV_WEBUI_CONF_REQ_OPT_TYPE] = {}
        self.handlers[const.DEV_WEBUI_CONF_REQ_OPT_TYPE]['request_handler'] = self.handle_webuiconf_query
        self.handlers[const.DEV_WEBUI_CONF_REQ_OPT_TYPE]['response_handler'] = self.webuiconf_query_response
        self.handlers[const.DEV_WEBUI_CONF_REQ_OPT_TYPE]['response_id'] = const.DEV_WEBUI_CONF_RESP_OPT_TYPE

        # diag request
        self.handlers[const.DEV_DIAG_REQ_OPT_TYPE] = {}
        self.handlers[const.DEV_DIAG_REQ_OPT_TYPE]['request_handler'] = self.handle_diag_request
        self.handlers[const.DEV_DIAG_REQ_OPT_TYPE]['response_handler'] = self.diag_request_response
        self.handlers[const.DEV_DIAG_REQ_OPT_TYPE]['response_id'] = const.DEV_DIAG_RESP_OPT_TYPE

        # reboot_request
        self.handlers[const.DEV_REBOOT_OPT_TYPE]  = {}
        self.handlers[const.DEV_REBOOT_OPT_TYPE]['request_handler']  = self.handle_reboot
        self.handlers[const.DEV_REBOOT_OPT_TYPE]['response_handler']  = None
        self.handlers[const.DEV_REBOOT_OPT_TYPE]['response_id']  = None

    def run(self):
        self.process_data()

    def terminate_conn(self, ike_id):
        arg = {}
        arg['ike-id'] = ike_id
        arg['timeout'] = 5
        ret_msg = self.sv.teminiate(arg)
        err = -1
        for k in ret_msg:
            if k['group'] == 'CFG' and "went offline" in k['msg']:
                err = 0
                break
        return err

    def get_productinfo_data(self):
        return self.productinfo_data

    def get_confinfo_data(self):
        return self.confinfo_data

    def get_capwapc(self):
        return self.capwapc_data

    def handle_diag_request(self, request):
        '''
        name: e0
        ip_type: 0 - dhcp, 2 - pppoe
        pppoe_username:
        pppoe_password:
        dnss
        '''
        data = json.loads(request['data'], encoding='utf-8')
        log_err("+++++++++>{}".format(data))
        ret = {}
        name = data['name']
        ret['name'] = name
        if name == 'e0':
            lname = "wan"
        elif name == 'e1':
            lname = "wan1"
        elif name == 'e2':
            lname = "wan2"
        else:
            log_warning('{} is not a wan'.format(name))
            ret['error_code'] = 1
            return ret

        if data['ip_type'] == 0: # dhcp
            try:
                param = {'config':'network', 'section':lname, 'values':{'proto':'dhcp', 'defaultroute':0}}
                ubus.call('uci', 'set', param)
                ubus.call('uci', 'commit', {'config':'network'})
                # reload network
                ubus.call('network', 'reload', {})
                time.sleep(5)
            except Exception, e:
                log_warning("name:{} diag failure, {}".format(name, e))
                ret['error_code'] = const.COMMON_FAILURE
                return ret

        elif data['ip_type'] == 2: # pppoe
            try:
                param = {'config':'network', 'section':lname, 'values':{'proto':'pppoe', 'username':data['pppoe_username'], 'password':data['pppoe_password'], 'defaultroute':0}}
                ubus.call('uci', 'set', param)
                ubus.call('uci', 'commit', {'config':'network'})
                # monitor log
                ps = subprocess.Popen('logread -f', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True,cwd='/tmp',preexec_fn=os.setsid)
                ubus.call('network', 'reload', {})
                ret['error_code'] = const.PPPOE_CAN_NOT_CONNECTED
                old = datetime.now()
                while True:
                    if (datetime.now() - old).seconds >= 60:
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        ret['error_code'] = const.PPPOE_CAN_NOT_CONNECTED # timeout
                        break
                    data = ps.stdout.readline()
                    # print "xxx>:{}:<xxx".format(data)
                    if data == b'':
                        if ps.poll() is not None:
                            break
                    elif data.find('Unable to complete PPPoE Discovery') != -1:
                        ret['error_code'] = const.PPPOE_DISCOVERY_ERROR # discovery error
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        break
                    elif data.find('Serial link appears to be disconnected') != -1:
                        ret['error_code'] = const.PPPOE_AUTH_ERR # LCP error
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        break
                    elif data.find('CHAP authentication failed: Access denied') != -1:
                        ret['error_code'] = const.PPPOE_AUTH_ERR # authentication error
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        break
                    elif data.find('Received bad configure-ack') != -1:
                        ret['error_code'] = const.COMMON_SUCCESS # authentication error
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        break
                return ret

            except Exception, e:
                log_warning("name:{} diag failure, {}".format(name, e))
                ret['error_code'] = const.PPPOE_CAN_NOT_CONNECTED
                return ret

        else: # other not support
            log_warning("ip_type:{} is not supported for diag".format(data['ip_type']))
            ret['error_code'] = const.COMMON_FAILURE
            return ret

        try:
            # get if status
            if_status = ubus.call('network.interface.{}'.format(lname), 'status', {})[0]
            # init ret
            ret['error_code'] = const.COMMON_SUCCESS
            ret['ip'] = if_status['ipv4-address'][0]['address']
            ns_int = if_status['ipv4-address'][0]['mask']
            ret['netmask'] =  socket.inet_ntoa(struct.pack('!I', (1<<32)-(1<<(32-ns_int))))
            ret['gateway'] = if_status['route'][0]['target']
            ret['dnss'] = ""
            for dns in if_status['dns-server']:
                if not ret['dnss']:
                    ret['dnss'] = dns
                else:
                    ret['dnss'] = ret['dnss'] + ',' + dns
            # revert config
            #ubus.call('uci', 'revert', {'config':'network'})
            #ubus.call('network', 'reload', {})
        except Exception, e:
            log_warning("name:{} diag failure, {}".format(name, e))
            ret['error_code'] = const.CAN_NOT_GET_IP
            return ret

        return ret

    def diag_request_response(self, ret, request, response_id):
        '''
        name:
        error_code: 0 - success, 1 - failure
        ip:
        netmask:
        gateway:
        dnss:
        '''
        json_data = ret
        msg = {}
        msg['operate_type'] = response_id
        msg['cookie_id'] = request['cookie_id']
        msg['timestamp'] = int(time.time())
        msg['data'] = json.dumps(json_data)
        self.mailbox.pub(const.STATUS_Q, (1, msg), timeout=0)
        return

    def handle_webuiconf_query(self, request):
        ret = 0
        return ret

    def webuiconf_parse(self, sid):
        network_conf={}
        dhcp_conf={}
        webui_conf={}
        try:
            network_conf = ubus.call('uci', 'get', {"config":"network"})[0]["values"]
            dhcp_conf = ubus.call('uci', 'get', {"config":"dhcp"})[0]["values"]
            webui_conf = ubus.call('uci', 'get', {"config":"webui_config"})[0]["values"]
        except Excetpion, e:
            log_err("can not get config by ubus {}".format(e))

        e_data = {}
        e_data['type'] = 0
        e_proto = network_conf[sid]['proto']
        if e_proto == "dhcp":
            e_data['ip_type'] = 0
        elif e_proto == "static":
            e_data['ip_type'] = 1
            e_data['ips'] = []
            e_data['ips'].append({})
            e_data['ips'][0]['ip'] = network_conf[sid]['ipaddr']
            e_data['ips'][0]['netmask'] = network_conf[sid]['netmask']
            if 'gateway' in network_conf[sid]:
                e_data['gateway'] = network_conf[sid]['gateway']
            if 'dns' in network_conf[sid]:
                e_data['dnss'] = ""
                for _dns in network_conf[sid]['dns']:
                    if not e_data['dnss']:
                        e_data['dnss'] = _dns
                    else:
                        e_data['dnss'] = e_data['dnss'] + "," + _dns
            if sid == 'lan4053':
                e_data['type'] = 1
                e_data['ips'][0]['ip'] = webui_conf[sid]['ipaddr']
                e_data['ips'][0]['netmask'] = webui_conf[sid]['netmask']
                e_data['dhcp_start'] = int(webui_conf[sid]['dhcp_start'])
                e_data['dhcp_server_enable'] = int(webui_conf[sid]['dhcp_server_enable'])
                e_data['dhcp_limit'] = int(webui_conf[sid]['dhcp_limit'])
                e_data['dhcp_leasetime'] = int(webui_conf[sid]['dhcp_leasetime'])
        elif e_proto == "pppoe":
            e_data['ip_type'] = 2
            e_data['pppoe_username'] = network_conf[sid]['username']
            e_data['pppoe_password'] = network_conf[sid]['password']
        return e_data

    def webuiconf_query_response(self, ret, request, response_id):
        json_data = {}
        try:
            json_data['hostname'] = ubus.call('uci', 'get', {"config":"system", "section":"@system[0]", "option":"device_name"})[0]['value']
        except Exception, e:
            log_err("ubus err {}".format(e))
        json_data['e0'] = self.webuiconf_parse('wan')
        json_data['e3'] = self.webuiconf_parse('lan4053')
        msg = {}
        msg['operate_type'] = response_id
        msg['cookie_id'] = request['cookie_id']
        msg['timestamp'] = int(time.time())
        msg['data'] = json.dumps(json_data)
        self.mailbox.pub(const.STATUS_Q, (1, msg), timeout=0)

    def handle_conf(self, request):
        self.confinfo_data = okos_utils.set_whole_confinfo(request['data'])
        okos_system_log_info("configuration data obtained")
        time.sleep(3)
        ret = os.system("{} -o {} {}".format(const.OKOS_CFGDIFF_SCRIPT, okos_utils.get_whole_conf_bak_path(), okos_utils.get_whole_conf_path()))
        if ret != 0:
            okos_system_log_err("configuration loaded failed")
            self.confinfo_data = okos_utils.rollback_whole_confinfo()
        else:
            okos_system_log_info("configuration loaded successfully")
        return ret

    def conf_response(self, ret, request, response_id):
        json_data = {}
        json_data['config_version'] = self.confinfo_data['config_version']
        json_data['error_code'] = ret
        msg = {}
        msg['operate_type'] = response_id
        msg['cookie_id'] = request['cookie_id']
        msg['timestamp'] = int(time.time())
        msg['data'] = json.dumps(json_data)
        self.mailbox.pub(const.STATUS_Q, (1, msg), timeout=0)

    def handle_reboot(self, request):
        ret = os.system('reboot')
        okos_system_log_info("device is reset from nms request")

    def process_data(self):
        while not self.term:
            try:
                request = self.mailbox.sub(const.CONF_REQUEST_Q)
                log_debug('request:{request}'.format(request=request))
                request_id = request['operate_type']
                if request_id in self.handlers:
                    ret = None
                    request_handler = self.handlers[request_id]['request_handler']
                    if request_handler:
                        ret = request_handler(request)
                    response_handler = self.handlers[request_id]['response_handler']
                    response_id = self.handlers[request_id]['response_id']
                    if response_handler and response_id is not None:
                        response_handler(ret, request, response_id)
                else:
                    log_warning("no register handler for {}".format(request))
            except Exception,e:
                log_warning("process_data:{}, {}".format(request, e))

