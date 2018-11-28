from okos_tools import *
from constant import const
from collections import defaultdict

class HostnameEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(HostnameEnv, self).__init__('Hostname Infor', desc=desc, raiseup=False, debug=debug)

class HostnameReporter(Timer):
    def __init__(self, name='HostnameRTimer', interval=10, debug=False):
        super(HostnameReporter, self).__init__(name=name, interval=interval, repeated=True, debug=debug)
        self.debug = debug
        self.syscall = SystemCall(debug=self.debug)
        self.cur_data = []
        self.url = 'http://clientdatabase.oakridge.io:8103/clientdatabase/v0/client/report'
        self.param = {'key':1}

    def handler(self, *args, **kwargs):
        new_dhcpleases = []
        data_json = {}
        data_json['clients'] = {}
        with HostnameEnv('Query hostname information', debug=self.debug):
            new = self.syscall.get_dhcpleases_entries()
            old = self.cur_data
            new_dhcpleases = [a for a in new if a not in old]
            data_json['clients'] = {i['mac']:{'hostname':i['hostname']} for i in new_dhcpleases if i['hostname'] != '*'}
            self.cur_data = new
        with HostnameEnv('Report hostname information', debug=self.debug):
            if data_json['clients']:
                post_url(self.url, param_data=self.param, json_data=data_json, files=None, debug=False)
