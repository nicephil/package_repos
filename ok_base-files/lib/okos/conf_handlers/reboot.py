from conf_handlers import ConfHandler
from constant import const
from okos_tools import *
import time
import os

class Reboot(ConfHandler):
    def __init__(self, mailbox):
        super(Reboot, self).__init__(mailbox, const.DEV_REBOOT_OPT_TYPE, 0, name='Reboot')
    def _handler(self, request):
        okos_system_log_info("device is reset from nms request")
        time.sleep(5)
        os.system('reboot')
