from conf_handlers import ConfHandler
from constant import const
from okos_tools import *
import json
import os


class Upgrade(ConfHandler):
    def __init__(self, mailbox):
        super(Upgrade, self).__init__(mailbox, const.DEV_UPGRADE_REQ_OPT_TYPE, const.DEV_UPGRADE_RESP_OPT_TYPE, name='Upgrade')
    def _handler(self, request):
        ret = 0
        data = json.loads(request['data'], encoding='utf-8')
        log_err("+++++++++>{}".format(data))
        url = data['url']
        timeout = data['timeout']
        okos_system_log_info("get upgrade firmware request")
        ret = os.system("wget -q -T {} -O - \'{}\' | tail -c +65 | tar xzf - -O > {}".format(timeout, url, const.CST_IMG_TMP_FILE))
        if ret != 0:
            okos_system_log_err("download firmware failed, errcode:{}".format(ret))
            os.system("(sleep 20;reboot)&")
            ret = 1
            return ret

        okos_system_log_info("downloaded firmware size:{}, writing firmware to disk".format(os.path.getsize(const.CST_IMG_TMP_FILE)))
        ret = os.system("(sleep 1;sysupgrade {} )&".format(const.CST_IMG_TMP_FILE))
        if ret != 0:
            okos_system_log_info("upgrade firmware failed, errcode:{}".format(ret))
        json_data = {}
        json_data['error_code'] = ret
        return json_data
