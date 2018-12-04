
from okos_tools import *
from constant import const
import pprint
import time
import json
from collections import defaultdict

pp = pprint.pprint

class ClientStatistic(Poster):
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
        super(ClientStatistic, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug, pri=1)
        self.debug = debug
        self.syscall = SystemCall(debug=self.debug)
        self.cur_data = defaultdict(list)
        self.counter = 0
        self.max_counter = report
        self.dump_file_name = '/tmp/client_statistic.{ts}.json'
        self.period = 0
        self.max_period = period
        self.actions = [
            {'interval':1,      'func':self._sample, 'counter': 0},
            {'interval':report, 'func':self._report, 'counter': 0},
            {'interval':period, 'func':self._period, 'counter': 0},
        ]

    def _period(self, cargo):
        '''
        At the end of statistic report period, do 
        1) cleanup job.
        '''
        self.syscall.remove_out_of_statistic_data(self.dump_file_name.format(ts='*'), self.max_period)
        return cargo
        

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
        return cargo

    def _sample(self, cargo):
        '''
        For very sample interval, we shoul do:
        1) save statistic data to local dict variable;
        '''
        cargo['sample'] = statistics = self.syscall.get_statistic_counters()
        map(lambda mac: self.cur_data[mac].append(statistics[mac]), statistics)
        return cargo

    def _action(self, cargo, fx):
        fx['counter'] = fx['counter']+1 if fx['counter'] < fx['interval'] else 1
        if fx['counter'] >= fx['interval']:
            fx['func'](cargo)
            return True
        else:
            return False

    def handler(self, *args, **kwargs):
        cargo = {}
        for action in self.actions:
            if not self._action(cargo, action):
                break
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

        
        


