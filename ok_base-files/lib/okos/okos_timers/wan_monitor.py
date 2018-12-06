from okos_tools import *
from constant import const
import pprint
import time
import json
from collections import defaultdict
import psutil
import speedtest

pp = pprint.pprint

class WanMonitorTimer(HierarchicPoster):
    def __init__(self, mailbox, operate_type=const.WAN_MONITOR_RPT_OPT_TYPE, 
                        name='WanMonitorTimer', debug=False, interval=10, pri=1):
        super(WanMonitorTimer, self).__init__(name, interval, mailbox, operate_type, pri, debug)
        self.debug = debug
        self.wans = filter(lambda p: p['type'] == const.DEV_CONF_PORT_TYPE['wan'], const.PORT_MAPPING)
        self.phys = [p['phy'] for p in self.wans]
        self.threshold_100m = (interval/10.0)*500*1000      # 500Kbps
        #self.syscall = SystemCall(debug=self.debug)
        self.old = defaultdict(lambda : {'rx':0, 'tx':0})
        self.status = defaultdict(int)
        self.tool = speedtest.Speedtest()
        self.tool.get_best_server()

        self.add_layer('counting', 1, self.counting)
        self.add_layer('detecting', 3, self.detecting)
        self.add_layer('sync_server', 20, self.sync_server)

    def sync_server(self, cargo):
        self.tool.get_best_server()
        self.debug and log_debug('Get new best server {info}'.format(info=self.tool.config['client']))
        return True

    def speed_test(self, status):
        port, stat = status
        if stat >= 3:
            self.tool.download()
            self.tool.upload()
            res = {
                'download': self.tool.results.download,
                'upload': self.tool.results.upload,
                'lattency': self.tool.results.server['latency'],
            }
            self.debug and log_debug('Speed test result: {res}'.format(res=res))
            return res
        else:
            self.debug and log_debug('Port {} is busy, pause speed testing.'.format(port))

    def detecting(self, cargo):
        res = map(lambda p: self.speed_test(p), self.status.iteritems())
        cargo['result'] = res[0] if res else None
        return True

    def cal_bw(self, new_data):
        '''
        :new_data:  ('eth0', {'rx': 46180641, 'tx': 24687105})
        '''
        port, data = new_data
        if data['tx'] == 0 and data['rx'] == 0:
            self.debug and log_debug('Port {port} is busy.'.format(port=port))
            self.status[port] = 0
        else:
            delta = {c: d - self.old[port][c] for c,d in data.iteritems()}
            free = filter(lambda d: d < self.threshold_100m, delta.values())
            if len(free) == 2:
                self.debug and log_debug('Port {port} is free.'.format(port=port))
                self.status[port] += 1
            else:
                self.debug and log_debug('Port {port} is busy.'.format(port=port))
                self.status[port] = 0
        self.old[port] = data

    def counting(self, cargo):
        #counters = psutil.net_io_counters(pernic=True)
        c = psutil.net_io_counters()
        counters = {'eth': {'tx': c.bytes_sent, 'rx': c.bytes_recv,}}
        #counters = {p: {'tx': c.bytes_sent, 'rx': c.bytes_recv,} for p,c in counters.iteritems() if p in self.phys}
        map(lambda c: self.cal_bw(c), counters.iteritems())
        return True

    @HierarchicPoster.hierarchic
    def handler(self, cargo, *args, **kwargs):
        if 'result' in cargo:
            return cargo['result']

if __name__ == '__main__':
    wm = WanMonitorTimer(None, debug=True)
    wm.start()
        

