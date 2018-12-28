#!/usr/bin/python

import threading
import argparse
from okos_tools import *
import os
from constant import const
from okos_conf import ConfMgr
import json
from okos_timers import *
import time

class PostMan(threading.Thread):
    def __init__(self, mailbox):
        super(PostMan, self).__init__()
        self.name = 'StatusMgr'
        self.term = False
        self.mailbox = mailbox
        self.oakmgr = Oakmgr(mailbox, debug=True)
        self.timers = [
            Redirector(interval=120, debug=True),
            HeartBeat(self.oakmgr, mailbox, debug=True),
            SystemHealthReporter(mailbox, interval=10, debug=True),
            Site2SiteVpnReporter(mailbox, interval=60, debug=True),
            IfStatusReporter(mailbox, interval=60, debug=True),
            DeviceReporter(mailbox, interval=60, debug=True),
            WiredClientReporter(mailbox, interval=10, debug=True),
            ClientStatistic(mailbox, interval=15, debug=True),
            DdnsStateReporter(mailbox, interval=60, debug=True),
            HostnameReporter(interval=10, debug=True),
            WanMonitorTimer(mailbox, debug=True),
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
