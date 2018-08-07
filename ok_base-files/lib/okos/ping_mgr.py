import Queue
import threading
import time
import okos_utils
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit
import json
from constant import const
import ubus

class PingMgr(threading.Thread):

    sites = ['google.com', 'sina.com.cn']
    running = True

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        self.process_data()

    def process_data(self):
        while self.running:
            for site in self.sites:
                param = {'site':site}
                result = ubus.call('ping_mgr', 'status', param)
                print result
            time.sleep(5)
