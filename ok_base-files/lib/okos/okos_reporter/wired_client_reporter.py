
from okos_tools import *
from constant import const
import time

class WiredClientReporter(Poster):
    def __init__(self, mailbox, operate_type=const.CLIENT_ONLINE_STATUS_RESP_OPT_TYPE, name='WiredClientTimer', interval=10, debug=False):
        super(WiredClientReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug, pri=5)
        self.debug = debug
        self.syscall = SystemCall(debug=self.debug)

        with ArpDb(debug=self.debug) as arp_db:
            arp_db.create_table()
    
    def handler(self, *args, **kwargs):
        millis = int(round(time.time() * 1000))
        res = ''
        with ExecEnv('WiredClients', desc='Query Arp Cache', raiseup=False, debug=self.debug) as X:
            new = [a for a in SystemCall().get_arp_entries() if int(a['Flags'], 16) == 2 for dev in const.LAN_IFACES if dev in a['Device']]
            X.output = new
            new = filter(lambda a: a['mac'], [{'mac':MacAddress(a['HW address']).mac, 'ip':a['IP address'], 'device':a['Device']} for a in new])
            with ArpDb(debug=self.debug) as arp_db:
                old = arp_db.get_all()
                up = [a for a in new if a not in old]
                down = [a for a in old if a not in new]
                arp_db.remove_olds(down)
                arp_db.add_news(up, millis)

        with ExecEnv('WiredClients', desc='Report clients', raiseup=False, debug=self.debug) as X:
            map(lambda x: x.setdefault('state', 1), down)
            map(lambda x: x.setdefault('state', 0), up)

            map(lambda x: self.syscall.add_statistic(x['ip'], x['mac']), up)
            map(lambda x: self.syscall.del_statistic(x['ip'], x['mac']), down)
            res = down + up
            X.output = res
            res = map(lambda x: clients_output_fmt(x, millis), res)
            
        return res and {'clients': res}
