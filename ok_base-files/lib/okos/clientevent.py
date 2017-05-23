#!/usr/bin/python

import os
import gc
import sys
import time
import struct
import urllib2
import binascii
from threading import Thread
from Queue import Queue
from okos_utils import get_auth_url, mac_to_byte, get_mac, get_portalscheme, \
    get_ssid
from syslog import syslog, LOG_INFO, LOG_WARNING, LOG_ERR, LOG_DEBUG


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
        self.name = mac

    def put_event(self, ath, event):
        # 1. new client event
        clientevent = ClientEvent(ath, event)
        queue = self.queue

        try:
            # 4. put into queue if queue is empty
            queue.put_nowait(clientevent)
        except Queue.Full:
            # 5. clean queue and put it
            tmp_event = queue.get_nowait()
            del(tmp_event)
            queue.put_nowait(clientevent)

    def handle_event(self):
        clientevent = self.queue.get()
        self.clientevent = clientevent
        # 1. handle connected event
        if clientevent.event == 'AP-STA-CONNECTED':
            # 1.1 query auth
            acl_type, time, tx_rate_limit, rx_ratelimit, remain_time = \
                self.query_auth()
            if acl_type == 1:
                # 1.2 set_whitelist
                self.set_whitelist(time, 1)
            elif acl_type == 3:
                # 1.3 set_blacklist
                self.set_blacklist(time, 1)
            elif acl_type == 0:
                # 1.4 none acl, so check
                if remain_time == 0:
                    self.set_whitelist(0, 0)
                else:
                    self.set_whitelist(remain_time, 1)
                self.set_blacklist(0, 0)
            # 1.5 set_ratelimit
            self.set_ratelimit(tx_rate_limit, rx_ratelimit)

        # 2. disconnected event
        elif clientevent.event == 'AP-STA-DISCONNECTED':
            # 2.1 cleanup
            # 2.2 stop handling and exit process
            self.term = True
            # self.set_whitelist(120, 1)
            # self.set_whitelist(0, 0)
            # self.set_blacklist(0, 0)
            # self.set_ratelimit(0, 0)
        else:
            syslog(LOG_WARNING, "Unknow Event on %s %s" %
                   (self.mac, clientevent.event))
        syslog(LOG_DEBUG, "mac:%s event:%s" % (self.mac, clientevent.event))
        del(clientevent)

    def query_auth(self):
        try:
            global auth_url
            url = '%s/authority?info=%s' % (auth_url, self.pack_info())
            response = urllib2.urlopen(url)
        except urllib2.HTTPError, e:
            syslog(LOG_WARNING, "HTTPError:%d %s" % (e.errno, e.strerror))
        response_str = response.read()
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
        domain_len = 0
        domain = ''
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
        syslog(LOG_DEBUG, repr(auth_mode))
        syslog(LOG_DEBUG, "remain_time:%s" % repr(remain_time))
        offset = struct.calcsize(fmt)
        fmt = '!%dsciii' % username_len
        username, acl_type, time, tx_rate_limit, rx_rate_limit = \
            struct.unpack_from(fmt, ss_str, offset)
        acl_type = ord(acl_type)
        syslog(LOG_DEBUG, "username:%s" % repr(username))
        syslog(LOG_DEBUG, "acl_type:%s" % repr(acl_type))
        syslog(LOG_DEBUG, "time:%s" % repr(time))
        syslog(LOG_DEBUG, "tx_rate_limit:%s" % repr(tx_rate_limit))
        syslog(LOG_DEBUG, "rx_rate_limit:%s" % repr(rx_rate_limit))
        return acl_type, time, tx_rate_limit, rx_rate_limit, remain_time

    def set_whitelist(self, time, action):
        os.system("/lib/okos/setwhitelist.sh %s %d %d" % (self.mac, time,
                                                          action))

    def set_blacklist(self, time, action):
        os.system("/lib/okos/setblacklist.sh %s %d %d" % (self.mac, time,
                                                          action))

    def set_ratelimit(self, tx_rate_limit, rx_ratelimit):
        pass

    def run(self):
        while not self.term:
            self.handle_event()


class Manager(object):
    """ Describes manager communication with pipe """
    def __init__(self, pipe_name):
        self.pipe_name = pipe_name
        self.client_dict = {}

    def create_pipe(self):
        try:
            os.mkfifo(self.pipe_name)
        except OSError, e:
            syslog(LOG_WARNING, "mkfifo error: %d %s" % (e.errno,
                                                         e.strerror))
            sys.exit(0)

        self.pipe_f = os.open(self.pipe_name, os.O_SYNC |
                              os.O_CREAT | os.O_RDWR)

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
            syslog(LOG_INFO, "ath:%s, mac:%s, event:%s" % (ath,
                                                           mac,
                                                           event))
            # 4. handle wifi up/down event
            if ath == '/lib/wifi' or event == 'AP-DISABLED':
                # free all existing clients
                for k in self.client_dict.keys():
                    self.client_dict[k].term = True
                self.client_dict.clear()
                continue

            # 5. handle client event
            if mac not in self.client_dict.keys():
                # 5.1 new one
                client = Client(mac)
                self.client_dict[mac] = client
                # 5.2 run it as daemon process
                client.start()
            else:
                client = self.client_dict[mac]
                if not client.is_alive():
                    del(client)
                    client = Client(mac)
                    self.client_dict[mac] = client

            # 6. add event into client event queue
            client.put_event(ath, event)

            # 7. clean up dead process
            for key in self.client_dict.keys():
                if not self.client_dict[key].is_alive():
                    del(self.client_dict[key])
            # 8. gc
            gc.collect()
            '''
            rt = gc.collect()
            print "%d unreachable" % rt
            garbages = gc.garbage
            print "\n%d garbages:" % len(garbages)
            for garbage in garbages:
                print str(garbage)
            '''


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
    # gc.set_debug(gc.DEBUG_COLLECTABLE | gc.DEBUG_UNCOLLECTABLE |
    # gc.DEBUG_INSTANCES | gc.DEBUG_OBJECTS | gc.DEBUG_SAVEALL)
    global device_mac
    device_mac = get_mac('br-lan1')
    global auth_url
    auth_url = get_auth_url()
    syslog(LOG_DEBUG, "device_mac:%s auth_url:%s" % (device_mac, auth_url))
    # 3. create manager object and go into event loop
    manager = Manager('/tmp/wifievent.pipe')
    manager.create_pipe()
    manager.handle_pipe_loop()


if __name__ == '__main__':
    main()
