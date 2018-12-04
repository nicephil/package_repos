
from okos_tools import *
from constant import const
import time

class DdnsStateReporter(Poster):
    def __init__(self, mailbox, operate_type=const.DEV_DDNS_STATUS_RESP_OPT_TYPE, name='DdnsStateTimer', interval=60, debug=False):
        super(DdnsStateReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug)
        self.debug = debug
        self.syscall = SystemCall(debug=self.debug)
    
    def _status(self, entry):
        cmd = ['set_ddns.sh', 'stat', entry['id'], '--domainname', entry['hostname'], '--ipaddr', entry['ip'],]
        res = self.syscall._output(cmd, comment='DDNS entry report - stat -', path=const.CONFIG_BIN_DIR)
        entry['status'] = 'success' in res and '0' or '1'
    def _updatetime(self, entry):
        cmd = ['set_ddns.sh', 'updatetime', entry['id'], ]
        res = self.syscall._output(cmd, comment='DDNS entry report - updatetime -', path=const.CONFIG_BIN_DIR)
        epoch_milliseconds = int(res.split(' ')[0] or '0') * 1000
        entry['updatetime'] = int(round(time.time() * 1000)) - epoch_milliseconds

    def handler(self, *args, **kwargs):
        '''
        :RETURN: {
            ddnss : [
                {'id': string, 'provider': string, 'hostname': string, 'status': '0|1', 'updatetime': long},
                ...,
            ]
        }
        '''
        res = None
        with ExecEnv('DdnsStateReporter', desc='Report DDNS Statue', raiseup=False, debug=self.debug) as X:
            conf = UciConfig('ddns')
            res = [{'id':_id, 'provider': c['service_name'], 'hostname': c['domain'], 'ip': c['ipaddr'],
                    } for _id, c in conf.iteritems()]
            X.output = res
            map(self._status, res)
            map(self._updatetime, res)

        return res and {'ddnss': res}
