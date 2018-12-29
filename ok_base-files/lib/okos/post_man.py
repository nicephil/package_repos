#!/usr/bin/python

import threading
from okos_tools import *
import os
from constant import const
import json
import time

class PostMan(threading.Thread):
    def __init__(self, mailbox, debug=False):
        super(PostMan, self).__init__()
        self.name = 'StatusMgr'
        self.term = False
        self.debug = debug
        self.mailbox = mailbox
        self.urgent_msg_pri = 10
        self.mailbox_timeout = 10
        self.oakmgr = Oakmgr(mailbox, debug=self.debug)
        self.timers = [
            HeartBeat(self.oakmgr, mailbox, debug=self.debug),
        ]

    def _round(self):
        with ExecEnv('Postman', desc='Comm with SDC', raiseup=False, debug=self.debug) as _X:
            msg = self.mailbox.sub(const.STATUS_Q)
            if not msg:
                time.sleep(self.mailbox_timeout)
                _X.log_err('ERROR: subscribe messages from STATUS_Q failed!\n\n')
                return
            if msg[0] < self.urgent_msg_pri:
                msgs = self.mailbox.get_all(const.STATUS_Q)
                msgs.append(msg)
                msgs = [m[1] for m in msgs]
                self.oakmgr.access(msgs)
            else:
                self.mailbox.pub(const.HEARTBEAT_Q, msg[1])

    def run(self):
        map(lambda x: x.start(), self.timers)

        while_loop = lambda : ((not self.term) and self._round()) or while_loop()
        #while_loop()
        while not self.term:
            self._round()


class HeartBeat(Timer):
    def __init__(self, oakmgr, mailbox, interval=const.HEARTBEAT_TIME, debug=False):
        super(HeartBeat, self).__init__('HeartBeatTimer', interval=interval, repeated=True, debug=debug)
        self.oakmgr = oakmgr
        self.mailbox = mailbox
        self.debug = debug

    def handler(self, *args, **kwargs):
        msgs = self.mailbox.get_all(const.HEARTBEAT_Q)
        msgs = [m[1] for m in msgs]
        self.oakmgr.access(msgs)

