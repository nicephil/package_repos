#!/usr/bin/python

import threading
import argparse
from okos_tools import *
import os
from constant import const
from okos_conf import ConfMgr
from post_man import PostMan
import json
from okos_timers import *
import time

class OkosMgr(object):
    def __init__(self, debug=False):
        super(OkosMgr, self).__init__()
        self.productinfo = PRODUCT_INFO
        self.debug = debug
        self.mailbox = MailBox()
        self.threads = [
            PostMan(self.mailbox, debug=True),
            ConfMgr(self.mailbox),
        ]
        self.timers = [
            Redirector(interval=120, debug=self.debug),
            SystemHealthReporter(self.mailbox, interval=10, debug=self.debug),
            Site2SiteVpnReporter(self.mailbox, interval=60, debug=self.debug),
            IfStatusReporter(self.mailbox, interval=60, debug=self.debug),
            DeviceReporter(self.mailbox, interval=60, debug=self.debug),
            WiredClientReporter(self.mailbox, interval=10, debug=self.debug),
            ClientStatistic(self.mailbox, interval=15, debug=self.debug),
            DdnsStateReporter(self.mailbox, interval=60, debug=self.debug),
            #HostnameReporter(interval=10, debug=self.debug),
            WanMonitorTimer(self.mailbox, debug=self.debug),
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
        OkosMgr(debug=True).join_threads()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Okos Main Daemon')
    parser.add_argument('-d', '--debug', action='store_true', help='debug mode')
    args = parser.parse_args()

    main(args)
