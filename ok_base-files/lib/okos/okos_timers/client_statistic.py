
from okos_tools import *
from constant import const
import pprint
import time
import json
from collections import defaultdict

pp = pprint.pprint

class ClientStatistic(HierarchicPoster):
    '''
    This timer is used to report clients traffic statistic automatically.
    The Timer will be run for every `interval` seconds to sample the statistic
    data. Data will be saved in local dict variable `self.cur_data` by mac.
    For every `report` number of interval, the data in self.cur_data will be
    saved local file named `/tmp/client_statistic.{ts}.json`.
    For every `period` number of report period, cleanup jos will be done.
    '''
    def __init__(self, mailbox, operate_type=const.CLIENT_STATISTIC_RPT_OPT_TYPE, 
                        name='ClientStatisticTimer', debug=False,
                        interval=15, report=1, period=3):
        super(ClientStatistic, self).__init__(name, interval, mailbox, operate_type, debug=debug, pri=1)
        self.debug = debug
        self.syscall = SystemCall(debug=self.debug)
        self.cur_data = defaultdict(list)
        self.max_file_num = 3
        self.dump_file_name = '/tmp/client_statistic.{ts}.json'

        self.add_layer('sample', 1, self._sample)
        self.add_layer('report', 1, self._report)
        self.add_layer('period', 3, self._period)

    def _period(self, cargo):
        '''
        At the end of statistic report period, do 
        1) cleanup job.
        '''
        self.syscall.remove_out_of_statistic_data(self.dump_file_name.format(ts='*'), self.max_file_num)
        return True
        
    def _report(self, cargo):
        '''
        For every report interval,
        1) save statistic to local file system.
        2) report to SDC?
        '''
        fname = self.dump_file_name.format(ts=int(round(time.time())))
        with open(fname, 'w+') as f:
            json.dump(self.cur_data, f)
        self.cur_data = defaultdict(list)
        cargo['report'] = fname
        return True

    def _sample(self, cargo):
        '''
        For very sample interval, we shoul do:
        1) save statistic data to local dict variable;
        '''
        cargo['sample'] = statistics = self.syscall.get_statistic_counters()
        map(lambda mac: self.cur_data[mac].append(statistics[mac]), statistics)
        return True

    @HierarchicPoster.hierarchic
    def handler(self, cargo, *args, **kwargs):
        '''
        report format:
        {
            'timestamp': long,
            'client_stats': [
                { 'mac': xx:xx:xx:xx:xx:xx, 'total_tx_bytes': long, 'total_tx_bytes': long, },
                ...,
            ],
        }'''
        if cargo['sample']:
            res = {'client_stats': cargo['sample'].values()}
            res['timestamp'] = res['client_stats'][0]['ts']
            return res

        
        


