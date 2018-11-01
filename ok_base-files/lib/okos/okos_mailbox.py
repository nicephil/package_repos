from okos_utils import log_debug, log_info, log_warning, log_err, log_crit
import Queue
from constant import const

class MailBox(object):
    def __init__(self):
        self.queues = {}
        self.queues[const.STATUS_Q] = Queue.PriorityQueue()
        self.queues[const.HEARTBEAT_Q] = Queue.Queue()
        self.queues[const.CONF_REQUEST_Q] = Queue.Queue()

    def pub(self, msgid, msgbody, timeout=None):
        ret = 0
        #log_debug("IN:publish msgid: '{msgid}', msgbody: {msgbody}".format(msgid=msgid, msgbody=msgbody))
        if not msgbody or (isinstance(msgbody, tuple) and not msgbody[1]):
            #log_debug("OUT:publish msgid: '{msgid}', msgbody: {msgbody}".format(msgid=msgid, msgbody=msgbody))
            return ret
        try:
            queue = self.queues[msgid]
            queue.put(msgbody, timeout=timeout)
        except Exception , e:
            log_warning("OUT:publish msgid: '{msgid}' queue put error:{e}".format(msgid=msgid, e=repr(e)))
            ret = -1
        #log_debug("OUT:publish msgid: '{msgid}', msgbody: {msgbody}".format(msgid=msgid, msgbody=msgbody))
        return ret

    def sub(self, msgid, timeout=None):
        msgbody = None
        #log_debug("IN:subcribe msgid: '{msgid}'".format(msgid=msgid))
        try:
            queue = self.queues[msgid]
            msgbody = queue.get(timeout=timeout)
        except Exception, e:
            log_warning("OUT:subscrib msgid: '{msgid}' queue get error:{e}".format(msgid=msgid, e=repr(e)))
            msgbody = None
        #log_debug("OUT:subcribe msgid: '{msgid}', msgbody: {msgbody}".format(msgid=msgid, msgbody=msgbody))
        return msgbody

    def get_all(self, msgid):
        msgbody = []
        #log_debug("IN:get_all msgid: '{msgid}'".format(msgid=msgid))
        q = self.queues[msgid]
        while not q.empty():
            msgbody.append(q.get_nowait())
        #log_debug("OUT:get_all msgid: '{msgid}', msgbody: {msgbody}".format(msgid=msgid, msgbody=msgbody))
        return msgbody
