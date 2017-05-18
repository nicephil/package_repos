#!/usr/bin/python2
# encoding:utf-8
# -*-coding:utf8-*-

import sys
import os
import time
import struct
import binascii
from multiprocessing import Process, Queue
from okos_utils import get_mac, get_ssid, get_portalscheme, mac_to_byte


class ClientEvent(object):
    """ Describes client event """
    def __init__(self, ath, event):
        self.ath = ath
        self.event = event


class Client(Process):
    """ Describes client """
    def __init__(self, mac):
        self.mac = mac
        self.queue = Queue.Queue(1)
        self.term = False
        self.clientevent = None

    def put_event(self, ath, event):
        # 1. new client event
        clientevent = ClientEvent(ath, event)
        queue = self.queue

        if queue.empty():
            # 4. put into queue if queue is empty
            queue.put_nowait(clientevent)
        else:
            # 5. clean queue and put it
            self.queue.get_nowait()
            self.queue.put_nowai(clientevent)

    def handle_event(self):
        clientevent = self.queue.get()
        self.clientevent = clientevent
        # 1. handle connected event
        if clientevent.event == "AP-STA-CONNECTED":
            # 1.1 query auth
            self.query_auth(self, clientevent)
            # 1.2 parse info from auth
            # 1.3 set_whitelist
            # 1.4 set_blacklist
            # 1.5 set_ratelimit

        # 2. disconnected event
        elif clientevent.event == "AP-STA-DISCONNECTED":
            # 2.1 cleanup
            # 2.2 stop handling and exit process
            self.term = True

    def query_auth(self):
        pass

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
        version = 4
        global device_mac
        client_mac = self.mac
        client_ip = ntonl(0)
        ssid = get_ssid(clientevent.ath)
        ssid_len = len(ssid)
        domain_len = 0
        domain = 0
        portal_scheme = get_portalscheme(clientevent.ath)
        portal_scheme_len = len(portal_scheme)
        bssid = get_bssid(clientevent.ah)
        fmt = '!c6s6sic%dsc%dsc%ds6s' % (
                                         ssid_len,
                                         domain_len,
                                         portal_scheme_len)
        byte_stream = struct.pack(fmt, chr(version), mac_to_byte(device_mac),
                                  mac_to_byte(client_mac), client_ip,
                                  chr(ssid_len), ssid, chr(domain_len), domain,
                                  chr(portal_scheme_len), portal_scheme,
                                  bssid)

        ss_str = ''
        for _, item in enumerate(byte_stream):
            ss_str += chr(ord(item) ^ 0xDA)
        return binascii.b2a_hex(ss_str)

    def unpack_auth(self, byte_str):
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
        pass

    def set_whitelist(self):
        pass

    def set_blacklist(self):
        pass

    def set_ratelimit(self):
        pass

    def run(self):
        while not self.term:
            self.handle_event()


class Manager(object):
    """ Describes manager communication with pipe """
    def __init__(self, pipe_name):
        self.pipe_name = pipe_name
        self.client_dict = {}
        self.create_pipe()

    def create_pipe(self):
        try:
            os.mkfifo(self.pipe_name)
        except OSError, e:
            print >>sys.stderr, "mkfifo error:", e

        self.pipe_f = os.open(self.pipe_name, os.O_SYNC |
                              os.O_CREAT | os.O_RDWR)

    def handle_pipe_loop(self):
        # loop processing pipe event
        while True:
            # 1. read pipe
            s = os.read(self.pipe_f, 128)

            if len(s) == 0:
                # 2. no char, sender is closed, so sleep
                time.sleep(1)
                continue

            # 3. parse content
            ath, mac, event = s.split(' ')

            if ath == "/lib/wifi":
                # 4. handle wifi up/down event
                # free all existing clients
                for k in self.client_dict.keys():
                    self.client_dict[k].terminate()
                self.client_dict.clear()
                continue

            # 5. handle client event
            if mac not in self.client_dict.keys():
                # 5.1 new one
                client = Client(mac)
                self.client_dict[mac] = client
                # 5.2 run it as daemon process
                client.daemon = True
                client.start()
            else:
                client = self.client_dict[mac]
                if not client.is_alive():
                    client.daemon = True
                    client.start()

            # 6. add event into client event queue
            client.put_event(ath, event)

            # 7. clean up dead process
            for key in self.client_dict.keys():
                if not self.client_dict[key].is_alive():
                    del(self.client_dict[key])


def main():
    # 1. daemonlize
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, e:
        print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror)
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
            print "Daemon PID %d" % pid
            sys.exit(0)
    except OSError, e:
        print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror)
        sys.exit(1)

    # 2. get mac info auth url from system
    global device_mac
    device_mac = get_mac("br-lan1")
    global auth_url
    auth_url = 'http://192.168.254.119:8080/auth-webapp/device/client/authority'
    # 3. create manager object and go into event loop
    manager = Manager("/tmp/wifievent.pipe")
    manager.handle_pipe_loop()


if __name__ == '__main__':
    main()
