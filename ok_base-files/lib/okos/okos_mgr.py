#!/usr/bin/python

import threading
import argparse
from okos_tools import *
import os
from constant import const
from okos_conf import ConfMgr
import socket
import json
from okos_reporter import *
import time

class Oakmgr(object):
    def __init__(self, mailbox, debug=False):
        super(Oakmgr, self).__init__()
        self.mailbox = mailbox
        self.device_mac = UciSection('productinfo', 'productinfo')['mac']
        self.pipe_name = '/tmp/okos_mgr.pipe'
        self.pipe_f = self.create_pipe(self.pipe_name)
        self.capwap = CAPWAP_SERVER.renew()
        self.first_access_nms = True
        self.debug = debug

    def create_pipe(self, pipe_name):
        pipe_f = None
        try:
            os.remove(self.pipe_name)
        except Exception, e:
            pass
        try:
            os.mkfifo(pipe_name)
            pipe_f = os.open(self.pipe_name, os.O_SYNC |os.O_CREAT | os.O_RDWR|os.O_NONBLOCK)
        except Exception, e:
            log_warning("mkfifo error: {}".format(e))
            pipe_f = None
        return pipe_f

    def access_pipe(self):
        try:
            s = os.read(self.pipe_f, 4096)
            self.debug and log_debug('PIPE : %s' % (s))
            s = s.strip('\n')
            json_d = json.loads(s, encoding='utf-8')
            self.debug and log_debug('JSON : %s' % (json_d))
        except Exception as e:
            json_d = {}
        return json_d

    def access(self, msgs):
        server = (self.capwap['mas_server'], 80, 'nms')
        #server = ('192.168.254.141', 8080, 'nms-webapp')
        url = 'http://{server}:{port}/{path}/api/device/router/info'.format(server=server[0], port=server[1], path=server[2])
        post_data = {
            'mac' : self.device_mac,
            'delay' : const.HEARTBEAT_DELAY,
            'list' : msgs,
        }
        requested = post_url(url, json_data=post_data, debug=self.debug)
        if self.first_access_nms:
            self.first_access_nms = False
            try:
                okos_system_log_info("connected to oakmgr @{}".format(socket.gethostbyname(server[0])))
            except Exception as e:
                okos_system_log_info("connected to oakmgr @{}".format(server[0]))
        if requested and 'error_code' in requested and requested['error_code'] == 1002:
            okos_system_log_warn("oakmgr-{} reject access".format(server))
        
        requested = self.access_pipe() or requested
        
        for r in requested.setdefault('list', []):
            self.debug and log_debug('REQUESTED data: %s' % (r))
            self.mailbox.pub(const.CONF_REQUEST_Q, r, timeout=0)

class HeartBeat(Timer):
    def __init__(self, oakmgr, mailbox, interval=const.HEARTBEAT_TIME, debug=False):
        super(HeartBeat, self).__init__('HeartBeatTimer', interval=interval, repeated=True, debug=debug)
        self.oakmgr = oakmgr
        self.mailbox = mailbox
        self.debug = debug
        
    def handler(self, *args, **kwargs):
        msgs = self.mailbox.get_all(const.HEARTBEAT_Q)
        self.oakmgr.access([m[1] for m in msgs])

class PostMan(threading.Thread):
    def __init__(self, mailbox):
        super(PostMan, self).__init__()
        self.name = 'StatusMgr'
        self.term = False
        self.mailbox = mailbox
        self.oakmgr = Oakmgr(mailbox, debug=True)
        self.timers = [
            Redirector(interval=120, debug=False),
            HeartBeat(self.oakmgr, mailbox, debug=False),
            SystemHealthReporter(mailbox, interval=10, debug=False), 
            Site2SiteVpnReporter(mailbox, interval=60, debug=False), 
            IfStatusReporter(mailbox, interval=60, debug=False), 
            DeviceReporter(mailbox, interval=60, debug=False),
            WiredClientReporter(mailbox, interval=10, debug=False),
            ClientStatistic(mailbox, interval=5, debug=False)
        ]


    def _round(self):
        msg = self.mailbox.sub(const.STATUS_Q)
        if not msg:
            time.sleep(10)
            log_err('ERROR: subscribe messages from STATUS_Q failed!\n\n')
            return
        if msg[0] < 10:
            msgs = self.mailbox.get_all(const.STATUS_Q)
            msgs.append(msg)
            self.oakmgr.access([m[1] for m in msgs])
        else:
            self.mailbox.pub(const.HEARTBEAT_Q, msg[1])

    def run(self):
        map(lambda x: x.start(), self.timers)

        while_loop = lambda : ((not self.term) and self._round()) or while_loop()
        #while_loop()
        while not self.term:
            self._round()
            


class OkosMgr(object):
    def __init__(self):
        super(OkosMgr, self).__init__()
        self.productinfo = PRODUCT_INFO
        self.mailbox = MailBox()
        self.threads = [
            PostMan(self.mailbox),
            ConfMgr(self.mailbox),
        ]
        self.timers = [
        ]

    def join_threads(self):
        os.system(const.INIT_SYS_SCRIPT)
        okos_system_log_info("oakos is up, version:{}".format(self.productinfo['swversion']))

        map(lambda t: t.start(), self.threads)
        map(lambda t: t.start(), self.timers)
        map(lambda t: t.join(), self.threads)
        

class debug(object):
    def __init__(self):
        super(debug, self).__init__()
    def log(self, *args):
        print args
    def pub(self, a1, a2, timeout):
        print a1, a2, timeout


def main(args):
    if not args.debug:
        pid_file = '/var/run/okos_mgr.pid'
        daemonlize(pid_file)
    with UbusEnv(debug=True):
        OkosMgr().join_threads()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Okos Main Daemon')
    parser.add_argument('-d', '--debug', action='store_true', help='debug mode')
    args = parser.parse_args()

    main(args)
