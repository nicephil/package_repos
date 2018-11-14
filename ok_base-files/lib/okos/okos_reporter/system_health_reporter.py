
from okos_tools import *
import psutil
from constant import const


class SystemEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(SystemEnv, self).__init__('System Infor', desc=desc, raiseup=False, debug=debug)


class SystemHealthReporter(Poster):
    def __init__(self, mailbox, operate_type=const.DEV_CPU_MEM_STATUS_RESP_OPT_TYPE, name='CpuMemTimer', interval=10, debug=False):
        super(SystemHealthReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True, pri=1, debug=debug)
        self.debug = debug
    def handler(self, *args, **kwargs):
        with SystemEnv('Query cpu & memory information', debug=self.debug):
            cpu_stats = psutil.cpu_percent(0)
            mem_stats = psutil.virtual_memory().percent
        data_json = {}
        with SystemEnv('Report cpu & memory information', debug=self.debug):
            data_json['cpu_load'] = int(cpu_stats)
            data_json['mem_load'] = int(mem_stats)
        return data_json
