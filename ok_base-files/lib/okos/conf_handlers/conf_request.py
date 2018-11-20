from conf_handlers import ConfHandler
from constant import const
from okos_tools import *
import time
import os


class ConfRequest(ConfHandler):
    def __init__(self, mailbox):
        super(ConfRequest, self).__init__(mailbox, const.DEV_CONF_OPT_TYPE, const.DEV_CONF_RESP_OPT_TYPE, name='ConfRequest')
    def _handler(self, request):
        self.confinfo_data = set_whole_confinfo(request['data'])
        okos_system_log_info("configuration data obtained")
        time.sleep(3)
        ret = os.system("{} -o {} {}".format(const.OKOS_CFGDIFF_SCRIPT, get_whole_conf_bak_path(), get_whole_conf_path()))
        if ret != 0:
            okos_system_log_err("configuration loaded failed")
            self.confinfo_data = rollback_whole_confinfo()
        else:
            okos_system_log_info("configuration loaded successfully")
        json_data = {}
        json_data['config_version'] = self.confinfo_data['config_version']
        json_data['error_code'] = ret
        return json_data