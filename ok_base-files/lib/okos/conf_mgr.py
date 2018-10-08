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
        time.sleep(3)
        ret = os.system("{} -o {} {}".format(const.OKOS_CFGDIFF_SCRIPT, okos_utils.get_whole_conf_bak_path(), okos_utils.get_whole_conf_path()))
        if ret != 0:
            log_err("conf failed")
            self.confinfo_data = okos_utils.rollback_whole_confinfo()
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

    def process_data(self):
        while not self.term:
            try:
                request = self.mailbox.sub(const.CONF_REQUEST_Q)
                log_debug('request:{request}'.format(request=request))
                request_id = request['operate_type']
                if request_id in self.handlers:
                    ret = 0
                    request_handler = self.handlers[request_id]['request_handler']
                    if request_handler:
                        ret = request_handler(request)
                    response_handler = self.handlers[request_id]['response_handler']
                    response_id = self.handlers[request_id]['response_id']
                    if response_handler and response_id is not None:
                        response_handler(ret, request, response_id)
                else:
                    log_warning("no register handler for {}".format(request_id))
            except Exception,e:
                log_warning("process_data:{}, {}".format(e, request_id))
                raise



