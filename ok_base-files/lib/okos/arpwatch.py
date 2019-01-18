#!/usr/bin/python

from threading import Thread
import socket
import struct
import binascii
import syslog
import sqlite3
import gc
import subprocess
import os

debug_mode = False

# From asm/socket.h
SO_ATTACH_FILTER = 26

def debug(s):
    global debug_mode
    syslog.syslog(syslog.LOG_DEBUG, s)
    if debug_mode:
        print s
def info(s):
    global debug_mode
    syslog.syslog(syslog.LOG_INFO, s)
    if debug_mode:
        print s
def warning(s):
    global debug_mode
    syslog.syslog(syslog.LOG_WARNING, s)
    if debug_mode:
        print s
def error(s):
    global debug_mode
    syslog.syslog(syslog.LOG_ERR, s)
    if debug_mode:
        print s



class Arpwatch(Thread):
    __slots__ = ('rawSocket', 'i_count')

    def __init__(self):
        Thread.__init__(self)
        self.rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self.name = "Arpwatch"
        self.i_count = 0
        self.attach_filter(self.rawSocket)

	def __del__(self):
		super.__del__()
		self.rawSocket.close()
		self.arp_db.close()

    def attach_filter(self, s):
        # XXX We generate the filter on the interface conf.iface
        # because tcpdump open the "any" interface and ppp interfaces
        # in cooked mode. As we use them in raw mode, the filter will not
        # work... one solution could be to use "any" interface and translate
        # the filter from cooked mode to raw mode
        try:
            f = os.popen("tcpdump -i br-lan1 -ddd -s 1600 'arp'")
        except OSError,msg:
            warning("Failed to execute tcpdump: (%s)" % msg)
            return
        lines = f.readlines()
        if f.close():
            raise Exception("Filter parse error")
        nb = int(lines[0])
        bpf = ""
        for l in lines[1:]:
            bpf += struct.pack("HBBI",*map(long,l.split()))
        # XXX. Argl! We need to give the kernel a pointer on the BPF,
        # python object header seems to be 20 bytes. 36 bytes for x86 64bits arch.
        #if scapy.arch.X86_64 or scapy.arch.ARM_64:
        #    bpfh = struct.pack("HL", nb, id(bpf)+36)
        #else:
        #    bpfh = struct.pack("HI", nb, id(bpf)+20)
        bpfh = struct.pack("HI", nb, id(bpf)+20)
        s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bpfh)

    def run(self):
        self.arp_db = DB('/tmp/stationinfo.db', 'STAINFO')
        while True:
            packet = self.rawSocket.recvfrom(2048)
            ethernet_header = packet[0][0:14]
            ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
            arp_header = packet[0][14:42]
            arp_detailed = None
            try:
                arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
            except Exception, e:
                continue
            # skip non-ARP packets
            ethertype = ethernet_detailed[2]
            if ethertype != '\x08\x06':
                continue
            #print "****************_ETHERNET_FRAME_****************"
            #print "Dest MAC:        ", binascii.hexlify(ethernet_detailed[0])
            #print "Source MAC:      ", binascii.hexlify(ethernet_detailed[1])
            #print "Type:            ", binascii.hexlify(ethertype)
            #print "************************************************"
            #print "******************_ARP_HEADER_******************"
            #print "Hardware type:   ", binascii.hexlify(arp_detailed[0])
            #print "Protocol type:   ", binascii.hexlify(arp_detailed[1])
            #print "Hardware size:   ", binascii.hexlify(arp_detailed[2])
            #print "Protocol size:   ", binascii.hexlify(arp_detailed[3])
            #print "Opcode:          ", binascii.hexlify(arp_detailed[4])
            #print "Source MAC:      ", binascii.hexlify(arp_detailed[5])
            #print "Source IP:       ", socket.inet_ntoa(arp_detailed[6])
            #print "Dest MAC:        ", binascii.hexlify(arp_detailed[7])
            #print "Dest IP:         ", socket.inet_ntoa(arp_detailed[8])
            #print "*************************************************\n"
            mac_h = binascii.hexlify(arp_detailed[5])
            mac = ':'.join(mac_h[i:i+2] for i in range(0,12,2))
            ip = socket.inet_ntoa(arp_detailed[6])
            self.arp_watch(mac, ip)
            self.i_count = self.i_count + 1
            if not (self.i_count % 40):
                self.i_count = 1
                rt = gc.collect()
                debug("%d unreachable" % rt)
                garbages = gc.garbage
                debug("\n%d garbages:" % len(garbages))

    def arp_watch(self, mac, ip):
        '''
        We put all the information together into database /tmp/stationinfo.db.
        1) hostapd will send event to ClienEvent to notify client join/leave.
        2) ClientEvent will INSERT a new entry for this client with IFNAME only.
        3) When ARP captured, we will judge whether it's wireless client or not
        through the database. Then, update IPADDR and/or HOSTNAME into it.
        4) WifiDog will help to update IPADDR either and other columns related
        to portal process.
        5) ClientEvent will collect and update other column on the way.
        6) If a client left, ClientEvent will DELETE its entry.
        '''
        old_mac, old_ip, old_hname, ifname = self.arp_db.query(mac)
        if old_mac and old_ip != ip:
            debug("IP Changed for [{mac} - {ip}]".format(ip=ip,mac=mac))
            self.arp_db.update_ip(mac, ip)
            hostname = self.get_hostname(ip)
            if hostname and hostname != old_hname:
                self.arp_db.update_hostname(mac, hostname)
            self.call_event(mac, ip, ifname)

    def check_output(self, cli):
        try:
            return subprocess.check_output(cli)
        except subprocess.CalledProcessError as err:
            #error('{cli} return error code ({rc})'.format( cli = ' '.join(cli), rc = err.returncode))
            return ''
        except Exception as e:
            error(str(e))
            return ''

    def call_event(self, mac, ip, ifname):
        '''Actually, Client_Event doesn't need ifname.
        It's just a ocuppitor to match the format of event from hostapd.
        '''
        return

    def get_hostname(self, ip):
        '''host 192.168.254.144
        '144.254.168.192.in-addr.arpa domain name pointer StevenMcBookPro.hz.oakridge.vip.\n'
        '''
        res = self.check_output(['host', ip])
        return res and res.split(' ')[-1][:-2] or ''

class DB(object):
    __slots__ = ('db_file', 'tname', 'cache', 'conn', 'cur')

    def __init__(self, db_file='/tmp/arptables.db', table_name='br-lan', cache=False):
        self.db_file = db_file
        self.tname = table_name
        self.cache = cache
        info("Tring to open connection to database <{}>".format(self.db_file))
        self.conn = sqlite3.connect(self.db_file)
        self.cur = self.conn.cursor()
        self.create_table()
        info("Connect to database successfully.")

    def close(self):
        if self.conn is not None:
            info("database closed")
            self.conn.close()

    def create_table(self):
        sql = '''CREATE TABLE IF NOT EXISTS '{tablename}' (
        MAC text PRIMARY KEY,
        IPADDR text,
        HOSTNAME text
        );'''.format(tablename=self.tname)
        info("Create table <{}> by [{}]".format(self.tname,sql))
        self.conn.execute(sql)
        #self.cur.execute(sql)
        self.conn.commit()
        if self.cache:
            info("Create cache...")
            self.cache = {row[0]: {'ip':row[1], 'hname':row[2], 'ifname':row[3]} for row in self.query()}
            info("Create successfully!")

    def query(self, mac=None):
        if self.cache and mac and mac in self.cache:
            return (mac, self.cache[mac]['ip'], self.cache[mac]['hname'])
        cond = mac and "WHERE MAC='{mac}' COLLATE NOCASE".format(mac=mac) or ''
        sql = '''SELECT MAC,IPADDR,HOSTNAME,IFNAME FROM '{tname}' {cond}
        '''.format(tname=self.tname,cond=cond)
        self.cur.execute(sql)
        res = self.cur.fetchall()
        return mac and (res and res[0] or ('','','','')) or res

    def new_entry(self, mac, ip, hostname):
        sql = '''INSERT OR REPLACE INTO '{tname}' (MAC, IP, HOSTNAME) VALUES
        ('{mac}', '{ip}', '{hostname}'
        );'''.format(tname=self.tname, mac=mac, ip=ip, hostname=hostname)
        self.conn.execute(sql)
        self.conn.commit()
        if self.cache:
            self.cache[mac] = {'ip':ip, 'hname':hostname}

    def ip_changed(self, mac, ip):
        sql = '''INSERT OR REPLACE INTO '{tname}' (MAC, IP, HOSTNAME) VALUES (
        '{mac}', '{ip}',
        (SELECT HOSTNAME FROM '{tname}' WHERE MAC = '{mac}' COLLATE NOCASE)
        )
        '''.format(tname=self.tname, mac=mac, ip=ip)
        self.conn.execute(sql)
        self.conn.commit()
        if self.cache:
            if mac in self.cache:
                self.cache[mac]['ip'] = ip
            else:
                self.cache[mac] = {'ip':ip}

    def update_hostname(self, mac, hostname):
        sql = '''UPDATE '{tname}' SET HOSTNAME='{hostname}' WHERE MAC='{mac}' COLLATE NOCASE
        '''.format(tname=self.tname,hostname=hostname,mac=mac)
        self.conn.execute(sql)
        self.conn.commit()
        if self.cache:
            if mac in self.cache:
                self.cache[mac]['hname'] = hostname

    def update_ip(self, mac, ip):
        sql = '''UPDATE '{tname}' SET IPADDR='{ip}' WHERE MAC='{mac}' COLLATE NOCASE
        '''.format(tname=self.tname,ip=ip,mac=mac)
        self.conn.execute(sql)
        self.conn.commit()
        if self.cache:
            if mac in self.cache:
                self.cache[mac]['ip'] = ip


