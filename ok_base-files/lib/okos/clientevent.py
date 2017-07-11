#!/usr/bin/python

import os
import gc
import sys
import time
import struct
import urllib2
import binascii
import threading
from threading import Thread
from Queue import Queue
from okos_utils import get_auth_url, mac_to_byte, get_mac, get_portalscheme, \
    get_ssid, get_domain
from syslog import syslog, LOG_INFO, LOG_WARNING, LOG_ERR, LOG_DEBUG
# import objgraph
# import pdb


class ClientEvent(object):
    """ Describes client event """
    def __init__(self, ath, event):
        self.ath = ath
        self.event = event


class Client(Thread):
    """ Describes client """
    def __init__(self, mac):
        Thread.__init__(self)
        self.mac = mac
        self.queue = Queue(1)
        self.term = False
        self.clientevent = None
        self.last_acl_type = 0
        self.name = mac

    def put_event(self, ath, event):
        # 1. new client event
        clientevent = ClientEvent(ath, event)
        queue = self.queue

        # 4. put into queue if queue is empty
        if queue.full():
            # 5. clean queue and put it
            syslog(LOG_WARNING, "Queue Full!")
            queue.queue.clear()
            queue.put_nowait(clientevent)
        else:
            queue.put_nowait(clientevent)

    # @profile
    def handle_event(self):
        clientevent = self.queue.get()
        self.clientevent = clientevent
        # 1. handle connected event
        if clientevent.event == 'AP-STA-CONNECTED':
            # 1.1 query auth
            acl_type, time, tx_rate_limit, rx_rate_limit, remain_time = \
                self.query_auth()
            syslog(LOG_DEBUG, "mac:%s acl_type:%s time:%s tx_rate_limit:%s \
                   rx_rate_limit:%s remain_time:%s" % (repr(self.mac),
                                                       repr(acl_type),
                                                       repr(time),
                                                       repr(tx_rate_limit),
                                                       repr(rx_rate_limit),
                                                       repr(remain_time)))
            self.last_acl_type = acl_type
            if acl_type == 1:
                # 1.2 set_whitelist
                self.set_whitelist(time, 1)
            elif acl_type == 3:
                # 1.3 set_blacklist
                self.set_blacklist(time, 1)
            elif acl_type == 0:
                # 1.4 none acl, so check
                self.set_blacklist(0, 0)
                if remain_time == 0:
                    self.set_whitelist(0, 0)
                else:
                    self.set_whitelist(remain_time, 1)
            # 1.5 set_ratelimit
            self.set_ratelimit(tx_rate_limit, rx_rate_limit,
                               clientevent.ath,
                               1)

        # 2. disconnected event
        elif clientevent.event == 'AP-STA-DISCONNECTED':
            # 2.1 stop handling and exit process
            if self.queue.empty():
                # 2.2 clean up
                if self.last_acl_type == 1:
                    self.set_whitelist(120, 1)
                    pass
                elif self.last_acl_type == 3:
                    # self.set_blacklist(0, 0)
                    pass
                elif self.last_acl_type == 0:
                    # self.set_whitelist(0, 0)
                    # self.set_blacklist(0, 0)
                    pass
                self.set_ratelimit(0, 0, clientevent.ath, 0)
                if self.queue.empty():
                    self.term = True
            else:
                syslog(LOG_DEBUG, "NEW EVENT Comming")
        elif clientevent.event == 'TERM':
            self.term = True
            sys.exit(0)
        # 3. Unknow Event
        else:
            syslog(LOG_WARNING, "Unknow Event on %s %s" %
                   (self.mac, clientevent.event))
        syslog(LOG_DEBUG, "-->mac:%s event:%s" % (self.mac, clientevent.event))

    def query_auth(self):
        try:
            global auth_url
            url = '%s/authority?info=%s' % (auth_url, self.pack_info())
            syslog(LOG_DEBUG, 'query url:%s' % url)
            response = urllib2.urlopen(url, timeout=3)
        except urllib2.HTTPError, e:
            syslog(LOG_WARNING, "HTTPError:%d %s" % (e.errno, e.strerror))
            return 0, 0, 0, 0, 0
        except Exception, e:
            syslog(LOG_WARNING, "HTTPError: %s" % str(e))
            return 0, 0, 0, 0, 0
        response_str = response.read()
        # hacky avoidance (https://bugs.python.org/issue1208304)
        response.fp._sock.recv = None
        response.close()
        del(response)
        return self.unpack_info(response_str)

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
        version = 4
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
            int tx_rate_limit;
        }
        """
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
        fmt = '!%dsciii' % username_len
        username, acl_type, time, tx_rate_limit, rx_rate_limit = \
            struct.unpack_from(fmt, ss_str, offset)
        acl_type = ord(acl_type)
        return acl_type, time, tx_rate_limit, rx_rate_limit, remain_time

    def set_whitelist(self, time, action):
        os.system("/lib/okos/setwhitelist.sh %s %d %d >/dev/null 2>&1" %
                  (self.mac, time,
                   action))
        pass

    def set_blacklist(self, time, action):
        os.system("/lib/okos/setblacklist.sh %s %d %d >/dev/null 2>&1" %
                  (self.mac, time,
                   action))
        pass

    def set_ratelimit(self, tx_rate_limit, rx_rate_limit, ath, action):
        os.system("/lib/okos/setratelimit.sh %s %d %d %s %d >/dev/null 2>&1" %
                  (self.mac,
                   tx_rate_limit,
                   rx_rate_limit,
                   ath,
                   action))
        pass

    def run(self):
        while not self.term:
            self.handle_event()


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

    # @profile
    def handle_pipe_loop(self):
        # loop processing pipe event
        while True:
            # 1. read pipe
            s = os.read(self.pipe_f, 128)
            s = s.strip('\n')

            # 2. no char, sender is closed, so sleep
            if len(s) == 0:
                time.sleep(1)
                continue

            # 3. parse content
            try:
                ath, mac, event = s.split(' ')
            except ValueError:
                ath = s
                mac = ''
                event = ''
            except KeyboardInterrupt:
                sys.exit(0)
            syslog(LOG_INFO, "==>ath:%s, mac:%s, event:%s" % (ath,
                                                              mac,
                                                              event))
            # 4. handle wifi driver down event
            if ath == '/lib/wifi':
                # free all existing clients
                for k in self.client_dict.keys():
                    self.client_dict[k].term = True
                    self.client_dict[k].put_event('ath00', 'TERM')
                self.client_dict.clear()
                # 4.1 retrieve the global information
                global auth_url
                auth_url = get_auth_url()
                global domain
                domain = get_domain()
                syslog(LOG_DEBUG, "device_mac:%s auth_url:%s domain:%s" %
                       (device_mac, auth_url, domain))
                # 4.2 system service restart
                os.system("/etc/init.d/whitelist restart >/dev/null 2>&1")
                os.system("/etc/init.d/qos restart >/dev/null 2>&1")
                # 4.3 collect memory
                gc.collect()

                for c in threading.enumerate():
                    syslog(LOG_DEBUG, 'FFF> %s' % str(c))

                continue
            elif event == 'AP-DISABLED' or len(mac) == 0:
                gc.collect()
                continue

            # 5. handle client event
            if mac not in self.client_dict.keys():
                # 5.1 new one
                client = Client(mac)
                self.client_dict[mac] = client
                # 5.2 run it
                client.daemon = True
                client.start()
            else:
                client = self.client_dict[mac]
                if (not client.is_alive()) or client.term:
                    client.term = True
                    del(client)
                    client = Client(mac)
                    self.client_dict[mac] = client
                    client.daemon = True
                    client.start()

            # 6. add event into client event queue
            client.put_event(ath, event)

            # 7. clean up dead process
            for key in self.client_dict.keys():
                if (not self.client_dict[key].is_alive()) or \
                   self.client_dict[key].term:
                    self.client_dict[key].term = True
                    del(self.client_dict[key])

            # 8. gc
            gc.collect()
            for c in threading.enumerate():
                syslog(LOG_DEBUG, 'CCC> %s' % str(c))
            # rt = gc.collect()
            # print "%d unreachable" % rt
            # garbages = gc.garbage
            # print "\n%d garbages:" % len(garbages)
            # for garbage in garbages:
            #     print str(garbage)
            # pdb.set_trace()


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
    # gc.set_debug(gc.DEBUG_COLLECTABLE | gc.DEBUG_UNCOLLECTABLE |
    #              gc.DEBUG_INSTANCES | gc.DEBUG_OBJECTS | gc.DEBUG_SAVEALL)
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
