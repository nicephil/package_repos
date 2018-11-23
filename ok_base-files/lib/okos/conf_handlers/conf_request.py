from conf_handlers import ConfHandler
from constant import const
from okos_tools import *
import time
import os


class ConfRequest(ConfHandler):
    def __init__(self, mailbox, debug=False):
        super(ConfRequest, self).__init__(mailbox, const.DEV_CONF_OPT_TYPE, const.DEV_CONF_RESP_OPT_TYPE, name='ConfRequest', debug=debug)
        self.conf = OKOS_CONFIG
        self.syscall = SystemCall(debug=debug)
        self.debug = debug

    def _handler(self, request):
        self.conf.config = request['data']
        okos_system_log_info("configuration data obtained")
        time.sleep(3)
        res = self.syscall.do_config(self.conf.conf_file, self.conf.bak_file)
        #ret = os.system("{} -o {} {}".format(const.OKOS_CFGDIFF_SCRIPT, get_whole_conf_bak_path(), get_whole_conf_path()))
        if res:
            okos_system_log_info("configuration loaded successfully")
        else:
            okos_system_log_err("configuration loaded failed")
            self.conf.rollback()
        json_data = {}
        json_data['config_version'] = self.conf.version
        json_data['error_code'] = res and '0' or '1'
        return json_data