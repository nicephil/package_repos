
from okos_tools import *
from constant import const
import time
import arptable
from pprint import pprint

class WiredClientReporter(Poster):
    '''
    This timer is used to report clients online status automatically.
    '''
    statistic_chains = ('statistic_tx', 'statistic_rx', 'statistic_tx_wan', 'statistic_rx_wan')
    def __init__(self, mailbox, operate_type=const.CLIENT_ONLINE_STATUS_RESP_OPT_TYPE, name='WiredClientTimer', interval=10, debug=False):
        super(WiredClientReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug, pri=5)
        self.debug = debug
        self.syscall = SystemCall(debug=self.debug)

        with ArpDb(debug=self.debug) as arp_db:
            arp_db.create_table()
    
    def get_arp_entries(self):
        '''
        return a list contains arp entries

        /proc/net/arp
        IP address       HW type     Flags       HW address            Mask     Device
        192.168.254.142  0x1         0x2         f0:d5:bf:ac:44:a0     *        eth0
        192.168.254.254  0x1         0x2         00:ec:ac:ce:80:8c     *        eth0

        [{"Mask": "*", "HW address": "00:ec:ac:ce:80:8c", "IP address": "192.168.254.254", "HW type": "0x1", "Flags": "0x2", "Device": "eth0"}]
        '''
        arpt = {}
        with ExecEnv('ARP table file', desc='get arp entries', raiseup=False, debug=self.debug) as X:
            arpt = arptable.get_arp_table()
            arpt = filter(lambda a: int(a['Flags'], 16) == 2, arpt)
            map(lambda a: a.setdefault('IFace', a['Device'].split('.')[0]), arpt)
            arpt = filter(lambda a: a['IFace'] in const.LAN_IFACES, arpt)
            arpt = filter(lambda a: a['mac'], [{'mac':MacAddress(a['HW address']).mac, 'ip':a['IP address'], 'device':a['Device']} for a in arpt])
        return arpt

    def _add_statistic_by_chain(self, ip, mac, chain):
        cmd = ['iptables', '-w', '-t', 'mangle', '-C', chain, 'tx' in chain and '-s' or '-d', ip, '-m', 'comment', '--comment', '"{}"'.format(mac), '-j', 'RETURN']
        if not self.syscall._check(cmd):
            cmd[4] = '-A'
            self.syscall._call(cmd)
    def add_statistic(self, *args):
        '''Add iptables entries to trace throughput of a client
        :params : (ip, mac)
        '''
        ip, mac = args
        map(lambda c: self._add_statistic_by_chain(ip, mac, c), self.statistic_chains)

    def _del_statistic_by_chain(self, ip, mac, chain):
        cmd = ['iptables', '-w', '-t', 'mangle', '-C', chain, 'tx' in chain and '-s' or '-d', ip, '-m', 'comment', '--comment', '"{}"'.format(mac), '-j', 'RETURN']
        if self.syscall._check(cmd):
            cmd[4] = '-D'
            self.syscall._call(cmd)
    def del_statistic(self, *args):
        '''Del iptables entries to trace throughput of a client
        :params : (ip, mac)
        '''
        ip, mac = args
        map(lambda c: self._del_statistic_by_chain(ip, mac, c), self.statistic_chains)

        
    def handler(self, *args, **kwargs):
        millis = int(round(time.time() * 1000))
        res = ''
        with ExecEnv('WiredClients', desc='Query Arp Cache', raiseup=False, debug=self.debug) as X:
            new = self.get_arp_entries()
            with ArpDb(debug=self.debug) as arp_db:
                old = arp_db.get_all()
                up = [a for a in new if a not in old]
                down = [a for a in old if a not in new]
                arp_db.remove_olds(down)
                arp_db.add_news(up, millis)

        with ExecEnv('WiredClients', desc='Report clients', raiseup=False, debug=self.debug) as X:
            map(lambda x: x.setdefault('state', 1), down)
            map(lambda x: x.setdefault('state', 0), up)

            map(lambda x: okos_sta_log_info("{{'sta_mac':'{mac}','logmsg':'is offline from {iface}'}}".format(mac=x['mac'],iface=x['device'])), down)
            map(lambda x: okos_sta_log_info("{{'sta_mac':'{mac}','logmsg':'is online from {iface}'}}".format(mac=x['mac'],iface=x['device'])), up)

            map(lambda x: self.del_statistic(x['ip'], x['mac']), down)
            map(lambda x: self.add_statistic(x['ip'], x['mac']), up)

            res = down + up
            res = map(lambda x: clients_output_fmt(x, millis), res)
            
        return res and {'clients': res}
