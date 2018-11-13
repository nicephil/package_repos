
from okos_tools import *
from constant import const

class WiredClientReporter(Poster):
    def __init__(self, mailbox, operate_type=const.CLIENT_ONLINE_STATUS_RESP_OPT_TYPE, name='WiredClientTimer', interval=60, debug=False):
        super(WiredClientReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug, pri=1)
        self.debug = debug

        with ArpDb(debug=self.debug) as arp_db:
            arp_db.create_table()

    def handler(self, *args, **kwargs):
        res = ''
        with ExecEnv('WiredClients', desc='Query Arp Cache', raiseup=False, debug=self.debug) as X:
            new = [a for a in SystemCall().get_arp_entries() if int(a['Flags'], 16) for dev in const.LAN_IFACES if dev in a['Device']]
            X.output = new
            new = [{'mac':MacAddress(a['HW address']).mac, 'ip':a['IP address'], 'device':a['Device']} for a in new]
            new = [a for a in new if a['mac']]
            with ArpDb(debug=True) as arp_db:
                old = arp_db.get_all()
                arp_db.update_all(new)

        with ExecEnv('WiredClients', desc='Report clients', raiseup=False, debug=self.debug) as X:
            up = [a for a in new if a not in old]
            down = [a for a in old if a not in new]
            map(lambda x: x.setdefault('state', 1), down)
            map(lambda x: x.setdefault('state', 0), up)

            res = down + up
            X.output = res

        return res and {'clients': res}
