#!/usr/bin/python

# import necessary modules
import os
import re
import gc
import sys
import time
import struct
import urllib2
import binascii
import threading
from threading import Thread
import Queue as qq
from Queue import Queue
from okos_utils import get_auth_url, mac_to_byte, get_mac, get_portalscheme, \
    get_ssid, get_domain
from syslog import syslog, LOG_INFO, LOG_WARNING, LOG_ERR, LOG_DEBUG
# import objgraph
# import pdb


# Class describes client's event object
class ClientEvent(object):
    """ Describes client event """
    __slots__ = ('ath', 'event', 'ppsk_key')

    def __init__(self, ath, event, ppsk_key):
        self.ath = ath
        self.event = event
        self.ppsk_key = ppsk_key


# Class describes client object with event handler
class Client(Thread):
    """ Describes client """
    __slots__ = ('mac', 'queue', 'term', 'clientevent', 'last_acl_type',
                 'last_tx_rate_limit', 'last_rx_rate_limit',
                 'last_tx_rate_limit_local', 'last_rx_rate_limit_local',
                 'last_ath', 'last_remain_time', 'last_username')

    def __init__(self, mac):
        Thread.__init__(self)
        self.mac = mac
        self.queue = Queue(1)
        self.term = False
        self.clientevent = None
        self.last_acl_type = 0
        self.last_tx_rate_limit = 0
        self.last_rx_rate_limit = 0
        self.last_tx_rate_limit_local = 0
        self.last_rx_rate_limit_local = 0
        self.last_ath = ''
        self.last_remain_time = 0
        self.last_username = ''
        self.name = mac

    # add a new event in queue
    def put_event(self, ath, event, ppsk_key=''):
        # 1. new client event
        clientevent = ClientEvent(ath, event, ppsk_key)
        queue = self.queue

        # 2. put into queue if queue is empty
        try:
            queue.put_nowait(clientevent)
        except qq.Full:
            tmp_event = self.queue.get_nowait()
            syslog(LOG_ERR, "%s:Queue Full, ignore %s-%s, put %s-%s" %
                   (self.mac, tmp_event.ath, tmp_event.event, clientevent.ath, clientevent.event))
            queue.put_nowait(clientevent)

    # query and save params
    def query_and_init(self, clientevent):
        if not self.last_ath or self.last_ath != clientevent.ath:
            err, acl_type, time, tx_rate_limit, rx_rate_limit, \
             tx_rate_limit_local, rx_rate_limit_local, remain_time, \
             username = self.query_auth(clientevent)
            syslog(LOG_ERR, "mac:%s err:%s acl_type:%s time:%s tx_rate_limit:%s \
                   rx_rate_limit:%s rx_rate_limit_local:%s \
                   tx_rate_limit_local:%s remain_time:%s username:%s" %
                   (repr(self.mac),
                    repr(err),
                    repr(acl_type),
                    repr(time),
                    repr(tx_rate_limit),
                    repr(rx_rate_limit),
                    repr(tx_rate_limit_local),
                    repr(rx_rate_limit_local),
                    repr(remain_time),
                    repr(username)))
            self.last_acl_type = acl_type
            self.last_tx_rate_limit = tx_rate_limit
            self.last_rx_rate_limit = rx_rate_limit
            self.last_tx_rate_limit_local = tx_rate_limit_local
            self.last_rx_rate_limit_local = rx_rate_limit_local
            self.last_remain_time = remain_time
            self.last_username = username
            self.last_ath = clientevent.ath
            if err == True:
                self.last_remain_time = 43200
                self.last_username = 'timeout'
            self.update_db(self.mac, self.last_ath, self.last_remain_time, self.last_username)

    # handler for AP-STA-CONNECTED event
    def handle_connected_event(self, clientevent):
        # 1.1 check if need to query auth again
        self.query_and_init(clientevent)
        # 1.2 set_whitelist
        if self.last_acl_type == 1:
            self.set_whitelist(0, 1)
        # 1.3 set_blacklist
        elif self.last_acl_type == 3:
            self.set_blacklist(120, 1, self.last_ath)
        # 1.4 none acl, so check
        elif self.last_acl_type == 0:
            self.set_blacklist(0, 0, self.last_ath)
            if self.last_remain_time == 0:
                self.set_whitelist(0, 0)
            else:
                self.set_whitelist(0, 1)
                self.notify_wifidog(self.mac, self.last_remain_time)

        # 1.5 set_ratelimit
        self.set_ratelimit(self.last_tx_rate_limit, self.last_rx_rate_limit,
                           self.last_tx_rate_limit_local,
                           self.last_rx_rate_limit_local,
                           self.last_ath,
                           1)

    # handle AP-STA-DISCONNECTED event
    def handle_disconnected_event(self, clientevent):
        # 2.1 clean up whitelist
        self.set_whitelist(0, 0)
        # 2.2 clean up blacklist
        # self.set_blacklist(0, 0 clientevent.ath)
        # 2.3 clean up wd db
        os.system("wdctl reset %s &" % self.mac)
        # 2.4 clean up ratelimit
        self.set_ratelimit(0, 0, 0, 0, clientevent.ath, 0)
        # 2.5 del client into client traffic track in iptables
        self.set_client_track(0)

        # check queue again
        if self.queue.empty():
            self.term = True

    # handle STA-IP-CHANGED event
    def handle_ip_changed_event(self, clientevent):
        # 4.1 check if need to query auth again
        self.query_and_init(clientevent)
        # 4.2 set_ratelimit
        self.set_ratelimit(self.last_tx_rate_limit, self.last_rx_rate_limit,
                           self.last_tx_rate_limit_local,
                           self.last_rx_rate_limit_local,
                           self.last_ath,
                           1)
        # 4.3 add client into client traffic track in iptables
        self.set_client_track(1)

    # @profile
    # main event handler
    def handle_event(self):
        try:
            clientevent = self.queue.get(block=True, timeout=30)
        except qq.Empty:
            self.term = True
            clientevent = ClientEvent('ath00', 'TERM', '')
            syslog(LOG_DEBUG, "%s: exit as no more event" % self.mac)

        self.clientevent = clientevent
        syslog(LOG_ERR, "++>mac:%s event:%s" % (self.mac, clientevent.event))

        # 1. handle connected event
        if clientevent.event == 'AP-STA-CONNECTED':
            self.handle_connected_event(clientevent)

        # 2. disconnected event
        elif clientevent.event == 'AP-STA-DISCONNECTED':
            self.handle_disconnected_event(clientevent)

        # 3. term event
        elif clientevent.event == 'TERM':
            self.term = True

        # 4. station ip changed event
        elif clientevent.event.find('STA-IP-CHANGED', 0) == 0:
            self.handle_ip_changed_event(clientevent)

        # 5. Unknow Event
        else:
            syslog(LOG_WARNING, "Unknow Event on %s %s" %
                   (self.mac, clientevent.event))

        syslog(LOG_ERR, "-->mac:%s event:%s" % (self.mac, clientevent.event))

    # query auth server and fetch info
    def query_auth(self, clientevent):
        try:
            global auth_url
            if len(clientevent.ppsk_key):
                url = '%s/authority?info=%s&ppsk_key=%s' % (auth_url,
                                                            self.pack_info(),
                                                            clientevent.ppsk_key)
            else:
                url = '%s/authority?info=%s' % (auth_url, self.pack_info())

            syslog(LOG_DEBUG, 'query url:%s' % url)
            response = urllib2.urlopen(url, timeout=5)
        except Exception, e:
            syslog(LOG_ERR, "HTTPError: %s" % str(e))
            return True, 0, 0, 0, 0, 0, 0, 0, ''
        response_str = response.read()
        # hacky avoidance (https://bugs.python.org/issue1208304)
        response.fp._sock.recv = None
        response.close()
        del(response)
        try:
            return self.unpack_info(response_str)
        except Exception, e:
            syslog(LOG_ERR, "UnpackError: %s" % str(e))
            return True, 0, 0, 0, 0, 0, 0, 0, ''

    # pack the info for auth query
    def pack_info(self):
        """
        struct info {
            char version;
            char device_mac[6];
            char client_mac[6];
            int clien_ip;
            char ssid_len;
            char ssid[];
            char domain_len;
            char domain[];
            char portal_scheme_len;
            char portal_scheme[];
            char bssid[6];
        }
        """
        clientevent = self.clientevent
        version = 5
        global device_mac
        client_mac = self.mac
        client_ip = 0
        ssid = get_ssid(clientevent.ath)
        ssid_len = len(ssid)
        global domain
        domain_len = len(domain)
        portal_scheme = get_portalscheme(clientevent.ath)
        portal_scheme_len = len(portal_scheme)
        bssid = get_mac(clientevent.ath)
        fmt = '!c6s6sic%dsc%dsc%ds6s' % (
                                         ssid_len,
                                         domain_len,
                                         portal_scheme_len)
        byte_stream = struct.pack(fmt, chr(version), mac_to_byte(device_mac),
                                  mac_to_byte(client_mac), client_ip,
                                  chr(ssid_len), ssid, chr(domain_len), domain,
                                  chr(portal_scheme_len), portal_scheme,
                                  mac_to_byte(bssid))

        ss_str = ''
        for _, item in enumerate(byte_stream):
            ss_str += chr(ord(item) ^ 0xDA)
        return binascii.b2a_hex(ss_str)

    # unpack the info from auth server
    def unpack_info(self, response_str):
        """
        struct auth {
            char version;
            char mac_num;
            char mac[][];
            int auth_mode;
            int remain_time;
            char username_len;
            char username[];
            char acl_type;
            int time;
            int tx_rate_limit;
            int rx_rate_limit;
            int tx_rate_limit_local;
            int rx_rate_limit_local;
        }
        """
        err = False
        _, response_str = response_str.strip('\n').split('=')
        byte_str = binascii.a2b_hex(response_str)
        ss_str = ''
        for _, item in enumerate(byte_str):
            ss_str += chr(ord(item) ^ 0xDA)
        fmt = '!cc6siic'  # version,mac_num,mac,auth_mode,remain_time,
        version, mac_num, mac, auth_mode, remain_time, username_len = \
            struct.unpack_from(fmt, ss_str)
        version = ord(version)
        mac_num = ord(mac_num)
        username_len = ord(username_len)
        offset = struct.calcsize(fmt)

        username = 0
        acl_type = 0
        time = 0
        tx_rate_limit = 0
        rx_rate_limit = 0
        tx_rate_limit_local = 0
        rx_rate_limit_local = 0

        fmt = '!%dsciii' % username_len
        fmt1 = '!%dsciiiii' % username_len
        if (len(ss_str) == (offset + struct.calcsize(fmt))):
            username, acl_type, time, tx_rate_limit, rx_rate_limit = \
                struct.unpack_from(fmt, ss_str, offset)
            acl_type = ord(acl_type)
        elif (len(ss_str) == (offset + struct.calcsize(fmt1))):
            username, acl_type, time, tx_rate_limit, rx_rate_limit,\
                tx_rate_limit_local, rx_rate_limit_local = \
                struct.unpack_from(fmt1, ss_str, offset)
            acl_type = ord(acl_type)
        else:
            syslog(LOG_ERR, "str_len:%d" % len(ss_str))
            err = True

        return err, acl_type, time, tx_rate_limit, rx_rate_limit, \
            tx_rate_limit_local, rx_rate_limit_local, remain_time, \
            username

    def update_db(self, mac, ath, remain_time, username):
        #sql_cmd="REPLACE INTO STAINFO (MAC,IFNAME,REMAIN_TIME,PORTAL_USER,PORTAL_STATUS) VALUES('%s','%s','%d','%s','%d')" % (mac, ath, remain_time, username, 1 if remain_time > 0 else 0)
        sql_cmd="UPDATE STAINFO SET IFNAME = '%s', REMAIN_TIME = '%d', PORTAL_USER = '%s', PORTAL_STATUS = '%d' WHERE MAC = '%s'" % (ath, remain_time, username, 1 if remain_time > 0 else 0, mac)
        cmd="sqlite3 /tmp/stationinfo.db \"BEGIN TRANSACTION;%s;COMMIT;\"" % sql_cmd
        os.system(cmd)
        pass

    def notify_wifidog(self, mac, remain_time):
        os.system("wdctl insert %s %d" % (mac, remain_time));
        pass

    def set_whitelist(self, time, action):
        os.system("/lib/okos/setwhitelist.sh %s %d %d >/dev/null 2>&1" %
                  (self.mac, time,
                   action))
        pass

    def set_blacklist(self, time, action, ath):
        os.system("/lib/okos/setblacklist.sh %s %d %d %s >/dev/null 2>&1" %
                  (self.mac, time,
                   action,
                   ath))
        pass

    def set_ratelimit(self, tx_rate_limit, rx_rate_limit,
                      tx_rate_limit_local, rx_rate_limit_local, ath, action):
        os.system("/lib/okos/setratelimit.sh %s %d %d %d \
                  %d %s %d >/dev/null 2>&1" %
                  (self.mac,
                   tx_rate_limit,
                   rx_rate_limit,
                   tx_rate_limit_local,
                   rx_rate_limit_local,
                   ath,
                   action))
        pass

    def set_client_track(self, action):
        if action:
            os.system(". /lib/okos/trafstats.sh; add_client_track %s" %
                      self.mac)
        else:
            os.system(". /lib/okos/trafstats.sh; del_client_track %s" %
                      self.mac)
        pass

    # main thread
    def run(self):
        while not self.term:
            try:
                self.handle_event()
            except Exception, e:
                syslog(LOG_ERR, "%s: Exception - %s" % (self.mac, str(e)))
        syslog(LOG_ERR, "%s: thread exit" % (self.mac))


# Class describes the manager
class Manager(object):
    """ Describes manager communication with pipe """
    def __init__(self):
        self.pipe_name = ''
        self.client_dict = {}

    def create_pipe(self, pipe_name):
        self.pipe_name = pipe_name
        try:
            os.mkfifo(self.pipe_name)
        except OSError, e:
            syslog(LOG_WARNING, "mkfifo error: %d %s" % (e.errno,
                                                         e.strerror))
            sys.exit(0)

        self.pipe_f = os.open(self.pipe_name, os.O_SYNC |
                              os.O_CREAT | os.O_RDWR)

    # handle /lib/wifi event
    def handle_wifi_down_event(self, ath, mac, event):
        # refetch auth_url and domain as config maybe changed
        global auth_url
        auth_url = get_auth_url()
        global domain
        domain = get_domain()
        syslog(LOG_DEBUG, "device_mac:%s auth_url:%s domain:%s" %
               (device_mac, auth_url, domain))

        # free all existing clients
        for k,v in self.client_dict.iteritems():
            client.put_event('ath00', 'TERM', '')
        self.client_dict.clear()
        gc.collect()

        for c in threading.enumerate():
            syslog(LOG_DEBUG, 'FFF> %s' % str(c))

    # handle AP-DISABLED event
    def handle_ap_disabled_event(self, ath, mac, event):
        # refetch auth_url and domain as config maybe changed
        global auth_url
        auth_url = get_auth_url()
        global domain
        domain = get_domain()
        syslog(LOG_DEBUG, "device_mac:%s auth_url:%s domain:%s" %
               (device_mac, auth_url, domain))

        return 0
        # get garbages info
        for c in threading.enumerate():
            syslog(LOG_DEBUG, 'FFF> %s' % str(c))
        rt = gc.collect()
        syslog(LOG_DEBUG, "%d unreachable" % rt)
        garbages = gc.garbage
        syslog(LOG_DEBUG, "\n%d garbages:" % len(garbages))
        i = 0
        for garbage in garbages:
            i = i + 1
            if i > 30:
                break
            if hasattr(garbage, "name"):
                syslog(LOG_DEBUG, "-----> obj:%s,name:%s" %
                       (garbage, garbage.name,))
            else:
                syslog(LOG_DEBUG, "%s" % str(garbage))

    # dispatch each client event
    def dispatch_client_event(self, ath, mac, event, ppsk_key):
        # 1. find or create Client object by client mac
        if mac not in self.client_dict or self.client_dict[mac].term:
            client = self.client_dict[mac] = Client(mac)
            client.daemon = True
            client.start()
        else:
            client = self.client_dict[mac]

        # 2. add event into client event queue
        client.put_event(ath, event, ppsk_key)

        # 3. clean up dead process
        self.client_dict = {k:v for k,v in self.client_dict.iteritems() if not v.term}

        # 4. gc
        gc.collect()
        # for c in threading.enumerate():
        #    syslog(LOG_DEBUG, 'CCC> %s' % str(c))
        # rt = gc.collect()
        # print "%d unreachable" % rt
        # garbages = gc.garbage
        # print "\n%d garbages:" % len(garbages)
        # for garbage in garbages:
        #     print str(garbage)
        # pdb.set_trace()

    def isValidMac(self, mac):
        if re.match(r"^\s*([0-9a-fA-F]{2,2}:){5,5}[0-9a-fA-F]{2,2}\s*$", mac):
            return True
        return False

    # @profile
    # pipe line loop
    def handle_pipe_loop(self):
        # loop processing pipe event
        while True:
            # 1. read pipe
            s = os.read(self.pipe_f, 168)
            s = s.strip('\n')

            # 2. no char, sender is closed, so sleep
            if len(s) == 0:
                time.sleep(1)
                continue

            # 3. parse content
            try:
                vs = s.split(' ')
                if len(vs) == 1:
                    ath = vs[0]
                    mac = ''
                    event = ''
                    ppsk_key = ''
                elif len(vs) == 2:
                    ath = vs[0]
                    mac = vs[1]
                    event = ''
                    ppsk_key = ''
                elif len(vs) == 3:
                    ath = vs[0]
                    mac = vs[1]
                    event = vs[2]
                    ppsk_key = ''
                elif len(vs) == 4:
                    ath = vs[0]
                    mac = vs[1]
                    event = vs[2]
                    ppsk_key = vs[3]
                else:
                    ath = s
                    mac = ''
                    event = ''
                    ppsk_key = ''

            except ValueError:
                ath = s
                mac = ''
                event = ''
                ppsk_key = ''
            except KeyboardInterrupt:
                sys.exit(0)

            syslog(LOG_ERR, "=++=>ath:%s, mac:%s, event:%s xx:%s" %
                   (ath,
                    mac,
                    event,
                    ppsk_key))

            # 4. handle wifi driver down event
            if ath == '/lib/wifi':
                self.handle_wifi_down_event(ath, mac, event)

            # 5. bypass AP-DISABLED event
            elif event == 'AP-DISABLED' or len(mac) == 0:
                self.handle_ap_disabled_event(ath, mac, event)

            # 6. handle client event
            elif len(ath) > 0 and self.isValidMac(mac) and len(event) > 0:
                self.dispatch_client_event(ath, mac, event, ppsk_key)

            # 7. Unknown
            else:
                syslog(LOG_ERR, "Unknown Event:%s,%s,%s,%s" % (ath,
                                                                mac,
                                                                event,
                                                                ppsk_key))
            # 8. add log
            syslog(LOG_ERR, "=--=>ath:%s, mac:%s, event:%s, xx:%s" %
                   (ath,
                    mac,
                    event,
                    ppsk_key))


def main():
    # 1. daemonlize
    daemon = True
    if len(sys.argv) > 1:
        daemon = False
    if daemon:
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            syslog(LOG_WARNING, "fork #1 failed: %d (%s)" %
                   (e.errno, e.strerror))
            sys.exit(1)
        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent, print eventual PID before
                syslog(LOG_INFO, "Daemon PID %d" % pid)
                sys.exit(0)
        except OSError, e:
            syslog(LOG_ERR, "fork #2 failed: %d (%s)" % (e.errno,
                                                         e.strerror))
            sys.exit(1)

    # 2. get mac info auth url from system
    gc.enable()
    # gc.set_debug(gc.DEBUG_LEAK)
    global device_mac
    device_mac = get_mac('br-lan1')
    global auth_url
    auth_url = get_auth_url()
    global domain
    domain = get_domain()
    syslog(LOG_DEBUG, "device_mac:%s auth_url:%s domain:%s" %
           (device_mac, auth_url, domain))
    # 3. create manager object and go into event loop
    manager = Manager()
    manager.create_pipe('/tmp/wifievent.pipe')
    manager.handle_pipe_loop()


if __name__ == '__main__':
    main()
