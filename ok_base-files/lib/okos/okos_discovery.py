#!/usr/bin/python

import threading
from okos_tools import *
import socket
import struct
import time

class InitializationError(Exception):
    def __init__(self, desc=''):
        super(InitializationError, self).__init__()
        self.value = desc
    def __str__(self):
        return repr(self.value)

class StateMachine(threading.Thread):
    def __init__(self, name='StateMachine', mailbox=None, debug=False):
        super(StateMachine, self).__init__()
        self.name = name
        self.mailbox = mailbox
        self.debug = debug
        self.handlers = {}
        self.startState = None
        self.endStates = []
        self.cargo = {}

    def add_state(self, name, handler, end_state=False):
        self.handlers[name] = handler
        if end_state:
            self.endStates.append(name)

    def set_start(self, name):
        self.startState = name


    def run(self):
        try:
            handler = self.handlers[self.startState]
        except:
            raise InitializationError(desc="must call .set_start() before .run()")

        self.debug and log_debug('State Machine [%s] is kicked off!' % (self.name))
        cargo = self.cargo
        while True:
            (newState, cargo) = handler(cargo)
            if newState in self.endStates:
                break
            else:
                handler = self.handlers[newState]


class Discovery(StateMachine):
    S_STARTUP = 'STARTUP'
    S_DISCOVER = 'DISCOVER'
    S_CONNECTING = 'CONNECTING'
    S_MANAGED = 'MANAGED'
    def __init__(self, name='Who is my SDC?', mailbox=None, interval=30, debug=False):
        super(Discovery, self).__init__(name=name, mailbox=mailbox, debug=debug)

        self.interval = interval

        self.product_info = PRODUCT_INFO.renew()
        self.capwap_server = CAPWAP_SERVER.renew()

        self.tsock_dev = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.MULTICAST_TTL = 2
        self.tsock_dev.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.MULTICAST_TTL)
        self.mcast_dev = ('224.0.0.135', 2016)
        self.mcast_to = lambda msg: self.tsock_dev.sendto(msg, self.mcast_dev)

        self.rsock_sdc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.rsock_sdc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.mcast_sdc = ('224.0.0.136', 2016)
        self.rsock_sdc.bind(self.mcast_sdc)
        mreq = struct.pack("4sl", socket.inet_aton(self.mcast_sdc[0]), socket.INADDR_ANY)
        self.rsock_sdc.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.rsock_sdc.settimeout(self.interval)
        self.recv = lambda : self.rsock_sdc.recv(10240)

        self.cargo = {
            'sdc': self.capwap_server,
            'product': self.product_info,
            'mcast_to': self.mcast_to,
            'recv': self.recv,
            }

        self.add_state(Discovery.S_STARTUP, self.startup)
        self.add_state(Discovery.S_DISCOVER, self.discover)
        self.add_state(Discovery.S_CONNECTING, self.connecting)
        self.add_state(Discovery.S_MANAGED, self.managed)
        self.set_start(Discovery.S_STARTUP)
    
    def log_state(self, state):
        log_debug('Goto state - %s -' % (state))
        print('Goto state - %s -' % (state))

    def startup(self, cargo):
        self.debug and self.log_state(Discovery.S_STARTUP)
        time.sleep(10)
        if cargo['sdc']['mas_server'] == '0.0.0.0':
            return (Discovery.S_DISCOVER, cargo)
        else:
            return (Discovery.S_CONNECTING, cargo)

    def discover(self, cargo):
        self.debug and self.log_state(Discovery.S_DISCOVER)
        time.sleep(10)
        return (Discovery.S_CONNECTING, cargo)

    def connecting(self, cargo):
        self.debug and self.log_state(Discovery.S_CONNECTING)
        time.sleep(10)
        return (Discovery.S_MANAGED, cargo)
    
    def managed(self, cargo):
        self.debug and self.log_state(Discovery.S_MANAGED)
        time.sleep(10)
        return (Discovery.S_CONNECTING, cargo)

if __name__ == '__main__':
    disc = Discovery(debug = True)
    disc.run()