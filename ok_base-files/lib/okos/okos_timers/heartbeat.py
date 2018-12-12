from okos_tools import *
from constant import const



class HeartBeat(Timer):
    def __init__(self, oakmgr, mailbox, interval=const.HEARTBEAT_TIME, debug=False):
        super(HeartBeat, self).__init__('HeartBeatTimer', interval=interval, repeated=True, debug=debug)
        self.oakmgr = oakmgr
        self.mailbox = mailbox
        self.debug = debug

    def handler(self, *args, **kwargs):
        msgs = self.mailbox.get_all(const.HEARTBEAT_Q)
        self.oakmgr.access([m[1] for m in msgs])