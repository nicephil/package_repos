import Queue
import threading
import time
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit
import okos_utils
import json
from constant import const
import vici
import os

class ConfMgr(threading.Thread):
    def __init__(self, mailbox):
        threading.Thread.__init__(self)
        self.name = 'ConfMgr'
        self.mailbox = mailbox
        self.term = False
        self.sv = vici.Session()
        self.productinfo_data = okos_utils.init_productinfo()
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
        ret = os.system('systemctl restart sysloader_mgr')

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
                log_warning("process_data:{}".format(e))



