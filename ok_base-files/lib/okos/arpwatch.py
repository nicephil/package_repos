#!/usr/bin/python
from scapy.all import *
import argparse
import subprocess
import re
import syslog
import sqlite3
import gc

debug_mode = False

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

arp_db = None
vap_pattern = re.compile('^Node Level Stats: [0-9a-zA-Z:]{17} [(]under VAP (ath[123][0-9])[)].*')

def check_output(cli):
    try:
        return subprocess.check_output(cli)
    except subprocess.CalledProcessError as err:
        #error('{cli} return error code ({rc})'.format( cli = ' '.join(cli), rc = err.returncode))
        return ''
    except Exception as e:
        error(str(e))
    return ''

def call_event(mac, ip, ifname):
    '''Actually, Client_Event doesn't need ifname.
    It's just a ocuppitor to match the format of event from hostapd.
    '''
    return
    ifname = ifname or get_vap_by_mac(mac);
    if not ifname:
        warning("Couldn't retrieve ifname anyway. Abort")
        return

    event = '{ifname} {mac} STA-IP-CHANGED_{ip}'.format(ip=ip,mac=mac,ifname=ifname)
    info("Call Event <{}>".format(event))
    try:
        with open('/tmp/wifievent.pipe', 'w') as p:
            p.write(event)
    except Exception as e:
        error("Call Event {} Failed".format(event))
        error(str(e))

def get_ifaces(ifname):
    pattern = re.compile('^({ifname}[0-9]{{1,4}})[ :].*$'.format(ifname=ifname), re.M)
    res = pattern.findall(check_output(['ifconfig']))
    info('Monitor ARP on {}'.format(res))
    return res

def get_vap_by_mac(mac):
    error("Couldn't retrieve ifname in database for [{}], using 'apstats'".format(mac))
    vap = vap_pattern.findall(check_output(['apstats', '-s', '-m', mac]))
    return vap and vap[0] or ''

def get_hostname(ip):
    '''host 192.168.254.144
    '144.254.168.192.in-addr.arpa domain name pointer StevenMcBookPro.hz.oakridge.io.\n'
    '''
    res = check_output(['host', ip])
    return res and res.split(' ')[-1][:-2] or ''

class db(object):
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

def is_valid_arp(mac, ip):
    if ip == '0.0.0.0': # ARP probe
        return False
    else:
        return True

def arp_watch_hook(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2):
        mac = pkt[ARP].hwsrc.lower()
        ip = pkt[ARP].psrc
        if is_valid_arp(mac, ip):
            arp_watch(mac, ip)
            global i_count
            i_count = i_count + 1
            if not (i_count % 40):
                i_count = 1
                rt = gc.collect()
                debug("%d unreachable" % rt)
                garbages = gc.garbage
                debug("\n%d garbages:" % len(garbages))

def arp_watch(mac, ip):
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
    global arp_db
    old_mac, old_ip, old_hname, ifname = arp_db.query(mac)

    if old_mac and old_ip != ip:
        debug("IP Changed for [{mac} - {ip}]".format(ip=ip,mac=mac))
        arp_db.update_ip(mac, ip)
        hostname = get_hostname(ip)
        if hostname and hostname != old_hname:
            arp_db.update_hostname(mac, hostname)
        call_event(mac, ip, ifname)

def _main(args):
    info("sniff filter for 'arp' added for {}".format(args.interface))
    if args.interface:
        sniff(filter='arp', store=0, stop_filter=arp_watch_hook, iface=get_ifaces(args.interface))
    else:
        sniff(filter='arp', store=0, stop_filter=arp_watch_hook)

def main(args):
    # gc.set_debug(gc.DEBUG_LEAK)
    global arp_db
    global i_count
    i_count = 1
    arp_db = db('/tmp/stationinfo.db', 'STAINFO', cache=args.cache)

    if args.debug:
        _main(args)
        arp_db.close()
    else:
        try:
            _main(args)
        except Exception as e:
            error(str(e))
            #raise e
        finally:
            arp_db.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Monitor ARP traffic')
    parser.add_argument('-d', '--debug', action='store_true', help='Enabel debug mode')
    parser.add_argument('-c', '--cache', action='store_true', help='Enabel cache')
    parser.add_argument('-i', '--interface', choices=['br-lan','ath'], help='Interface type', required=True)
    args = parser.parse_args()

    args.cache = False
    debug_mode = args.debug
    main(args)

