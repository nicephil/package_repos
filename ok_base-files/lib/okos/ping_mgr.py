import threading
import time
from okos_tools import log_info
import ping

class PingMgr(threading.Thread):

    sites = ['google.com', 'sina.com.cn']
    running = True

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        self.process_data()

    def process_data(self):
        while self.running:
            try:
                for site in self.sites:
                    loss, mtt, att = ping.quiet_ping(site)
                time.sleep(5)
            except Exception,e:
                log_info("ping is abort as {}".format(e))

