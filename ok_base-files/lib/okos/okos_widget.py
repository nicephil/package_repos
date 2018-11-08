#!/usr/bin/python
import argparse
import threading
from okos_env import SystemCall
from okos_logger import log_debug, logit
from okos_timer import ReportTimer
from constant import const
import time
import signal 
import sys

class OkosWidget(threading.Thread):
    def __init__(self, mailbox):
        super(OkosWidget, self).__init__()
        self.setName('OkosWidget')
        self.term = False
        self.mailbox = mailbox
        self.timers = [
            ReportTimer('ClientReporter', 6, self.client_report_timer_func, self.mailbox, const.CLIENT_ONLINE_STATUS_RESP_OPT_TYPE),
        ]

    def run(self):
        log_debug('You are running {}\n'.format(self.name))
        for timer in self.timers:
            timer.start()
        while not self.term:
            time.sleep(60)
            log_debug('R u ready to die?')

    def client_report_timer_func(self):
        arpt = SystemCall().get_arp_entries()
        return {'arp_entries': arpt}

class _OkosWidgetDebug(object):
    def __init__(self):
        super(_OkosWidgetDebug, self).__init__()
    def log(self, *args):
        print args
    def pub(self, msgid, msgbody, timeout=None):
        print msgid, msgbody

if __name__ == '__main__':
    def signal_handler(signal, frame):
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    debug = _OkosWidgetDebug()
    log_debug = debug.log
    
    okos_widget = OkosWidget(debug)
    okos_widget.start()
    while True:
        time.sleep(1)
    log_debug('bye')

