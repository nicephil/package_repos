
from okos_tools import *
from constant import const
import pprint
import time
import json

pp = pprint.pprint

class ClientStatistic(Poster):
    def __init__(self, mailbox, operate_type=const.CLIENT_ONLINE_STATUS_RESP_OPT_TYPE, name='ClientStatisticTimer', interval=5, report=6, period=3, debug=False):
        super(ClientStatistic, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug, pri=1)
        self.debug = debug
        self.syscall = SystemCall(debug=self.debug)
        self.cur_data = {}
        self.counter = 0
        self.max_counter = report
        self.dump_file_name = '/tmp/client_statistic.{ts}.json'
        self.period = 0
        self.max_period = period

    def _report(self):
        ts = int(time.time())
        with open(self.dump_file_name.format(ts=ts), 'w+') as f:
            json.dump(self.cur_data, f)
        self.cur_data = {}

    def _period(self):
        self.syscall.remove_out_of_statistic_data(self.dump_file_name.format(ts='*'), self.max_period)

    def _sample(self):
        statistics = self.syscall.get_statistic_counters()
        map(lambda mac: self.cur_data.setdefault(mac, []).append(statistics[mac]), statistics)

    def report(self):
        self._report()
        self.period = self.period < self.max_period and self.period+1 or 1
        self.period >= self.max_period and self._period()

    def handler(self, *args, **kwargs):
        self._sample()
        self.counter = self.counter < self.max_counter and self.counter+1 or 1
        self.counter >= self.max_counter and self.report()
        


