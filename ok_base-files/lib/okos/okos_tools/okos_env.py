from okos_logger import log_debug, log_err, log_warning
import time
import json
from constant import const
import subprocess
import socket
import re
import arptable
import csv


class ExecEnv(object):
    def __init__(self, prefix, cxt=None, desc='', raiseup=True, debug=False):
        super(ExecEnv, self).__init__()
        self.desc = desc
        self.cxt = cxt
        self.prefix = prefix
        self.raiseup = raiseup
        self.debug = debug

    @property
    def output(self):
        return self.cxt
    @output.setter
    def output(self, value):
        self.cxt = value

    def log_debug(self, c):
        log_debug('[%s] %s : %s' % (self.prefix, self.desc, c))
    def log_warning(self, c):
        log_warning('[%s] %s WARNING: %s' % (self.prefix, self.desc, c))
    def log_err(self, c):
        log_err('[%s] %s ERROR: %s' % (self.prefix, self.desc, c))

    def __enter__(self):
        self.debug and log_debug('[%s] %s - start -' % (self.prefix, self.desc))
        return self
    def __exit__(self, exception_type, value, traceback):
        (self.cxt and self.debug) and log_debug('[%s] context:\n%s\n' % (self.prefix, self.cxt))
        if exception_type:
            #log_crit('[%s] exception: <%s> : %s\n%s' % (self.prefix, exception_type, value, traceback.format_exc()))
            #log_crit('[%s] exception: <%s> : %s\n%s' % (self.prefix, exception_type, value, str(traceback)))
            self.cxt and log_debug('[%s] context:\n%s\n' % (self.prefix, self.cxt))
            self.log_err('[%s] exception :> %s >< %s <%s:%s>' % (self.prefix, exception_type, value, traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))
            self.log_err('[%s] %s - failed -' % (self.prefix, self.desc))
            return not self.raiseup
        self.debug and log_debug('[%s] %s - done -' % (self.prefix, self.desc))
        return True

class SystemCallEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(SystemCallEnv, self).__init__('System Call', desc=desc, debug=debug)


class SystemCall(object):
    def __init__(self, debug=False):
        super(SystemCall, self).__init__()
        self.debug = debug
    
    def _call(self, cmd, comment='', path='', shell=False):
        '''
        cmd = ['/lib/okos/bin/set_..._.sh', '33', '201'] ; shell = False
        cmd = ['/lib/okos/bin/set_..._.sh 33 201'] ; shell = True
        '''
        
        self.debug and comment and log_debug(comment)
        self.debug and log_debug("System Call - %s - start " % (cmd))
        try:
            cmd = [str(c) for c in cmd]
            if not cmd[0].startswith('/') and path:
                cmd[0] = path + cmd[0]
            res = subprocess.check_call(cmd, shell=shell)
        except subprocess.CalledProcessError as e:
            log_warning("Execute System Call - %s - failed!" % (e.cmd))
            return False
        except Exception as e:
            log_warning("Execute System Call - %s - failed with %s!" % (cmd, type(e).__name__))
            return False
        self.debug and log_debug("System Call - %s - return %d" % (cmd, res))
        return res == 0 and True or False

    def _output(self, cmd, comment='', path='', shell=False):
        '''
        cmd = ['/lib/okos/bin/set_..._.sh', '33', '201'] ; shell = False
        cmd = ['/lib/okos/bin/set_..._.sh 33 201'] ; shell = True
        '''
        
        self.debug and comment and log_debug(comment)
        self.debug and log_debug("System Output - %s - Start" % (cmd))
        try:
            cmd = [str(c) for c in cmd]
            if not cmd[0].startswith('/') and path:
                cmd[0] = path + cmd[0]
            res = subprocess.check_output(cmd, shell=shell)
        except subprocess.CalledProcessError as e:
            log_warning("Execute System Output - %s - failed[%s] :> %s" % (e.cmd, e.returncode, e.output))
            return ''
        except Exception as e:
            log_warning("Execute System Output - %s - failed with %s!" % (cmd, type(e).__name__))
            return ''
        self.debug and log_debug("System Output - %s - return %s" % (cmd, res))
        return res
    
    def localip2target(self, target):
        '''
        Get local information about route to target
        noly support ip address of target
        example:
            gateway, interface, localip = SystemCall().localip2taregt('13.112.4.123')

        '''
        p = const.FMT_PATTERN['ipaddr']
        if not p.match(target):
            target = socket.gethostbyname(target)
        p = re.compile('^[0-9.]{7,15}[ ]+via[ ]+([0-9.]{7,15})[ ]+dev[ ]+([a-z_0-9]+)[ ]+src[ ]+([0-9.]{7,15})')
        res = p.match(self._output(['ip', 'route', 'get', target]))
        return res and res.groups() or ('','','')
    def ip_netmask_4_iface(self, iface):
        '''
        ipaddress, netmask = SystemCall().ip_netmask_4_iface('eth0')
        '''
        p = re.compile('inet ([0-9.]{7,15})[/]([0-9]{2}) ')
        res = p.search(self._output(['ip', 'address', 'show', iface]))
        return res and res.groups() or ('','')


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
        with SystemCallEnv('get arp entries', debug=self.debug) as e:
            arpt = arptable.get_arp_table()
        return arpt
    
    def add_statistic(self, *args):
        '''Add iptables entries to trace throughput of a client
        :params : (ip, mac)
        '''
        ip, mac = args
        self._call(['iptables', '-t', 'mangle', '-A', 'statistic', '-s', ip, '-m', 'comment', '--comment', '"{}"'.format(mac), '-j', 'RETURN'])
        self._call(['iptables', '-t', 'mangle', '-A', 'statistic', '-d', ip, '-m', 'comment', '--comment', '"{}"'.format(mac), '-j', 'RETURN'])

    def del_statistic(self, *args):
        '''Del iptables entries to trace throughput of a client
        :params : (ip, mac)
        '''
        ip, mac = args
        self._call(['iptables', '-t', 'mangle', '-D', 'statistic', '-s', ip, '-m', 'comment', '--comment', '"{}"'.format(mac), '-j', 'RETURN'])
        self._call(['iptables', '-t', 'mangle', '-D', 'statistic', '-d', ip, '-m', 'comment', '--comment', '"{}"'.format(mac), '-j', 'RETURN'])
    
    def get_statistic_counters(self):
        '''
        INPUT:
        Chain statistic (1 references)
        pkts bytes target     prot opt in     out     source               destination         
            0     0 RETURN     all  --  *      *       172.16.100.168       0.0.0.0/0                  /* 00:0e:c6:d0:ec:a8 */
            0     0 RETURN     all  --  *      *       0.0.0.0/0            172.16.100.168          /* 00:0e:c6:d0:ec:a8 */
        After csv:
        [
        {'opt': '--', 'destination': '0.0.0.0/0', 'target': 'RETURN', 'prot': 'all', 'bytes': '0', 'source': '172.16.100.168', None: [''], 'in': '*', 'pkts': '0', 'out': '*'}, 
        {'opt': '--', 'destination': '172.16.100.168', 'target': 'RETURN', 'prot': 'all', 'bytes': '0', 'source': '0.0.0.0/0', None: [''], 'in': '*', 'pkts': '0', 'out': '*'}
        ]
        :return:
        {
            mac1 : {'tx_bytes': ?, 'tx_pkts': ?, 'rx_bytes': ?, 'rx_pkts': ?, 'ip': x.x.x.x, 'ts':???},
            ...,
            macN : {'tx_bytes': ?, 'tx_pkts': ?, 'rx_bytes': ?, 'rx_pkts': ?, 'ip': x.x.x.x, 'ts':???},
        }
        '''
        ts = int(time.time())
        ipt = self._output(['iptables', '-t', 'mangle', '-L', 'statistic', '-vn'])
        ipt = ipt.split('\n')[2:]

        # iptables v1.4.21
        names = ['pkts', 'bytes', 'target', 'prot', 'opt', 'in', 'out', 'source', 'destination', ]

        reader = csv.DictReader(ipt, fieldnames=names, skipinitialspace=True, delimiter=' ')

        total = [block for block in reader]

        tx = {t[None][1]: {'tx_bytes': t['bytes'], 'tx_pkts': t['pkts'], 'ip': t['source'], 'ts': ts} for t in total if t['destination'] == '0.0.0.0/0'}
        rx = {t[None][1]: {'rx_bytes': t['bytes'], 'rx_pkts': t['pkts'], 'ip': t['destination'], 'ts': ts} for t in total if t['source'] == '0.0.0.0/0'}
        map(lambda mac: mac in rx and tx[mac].update(rx[mac]), tx)

        return tx

    def remove_out_of_statistic_data(self, filename, num):
        files = self._output(['ls %s' % (filename)], shell=True).split('\n')
        files = [f for f in files if f]
        old = files[:-num]
        map(lambda f: self._call(['rm', f]), old)