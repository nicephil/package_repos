from okos_tools import log_debug, log_info, log_warning, log_err, log_crit
import Queue
from constant import const

class MailBox(object):
    def __init__(self):
        self.queues = {}
        self.queues[const.STATUS_Q] = Queue.PriorityQueue()
        self.queues[const.HEARTBEAT_Q] = Queue.PriorityQueue()
        self.queues[const.CONF_REQUEST_Q] = Queue.PriorityQueue()

    def pub(self, msgid, msgbody, timeout=None):
        '''Example:
        Mailbox().put(const.STATUS_Q, (100, 'hello! world')) # Public message 'hello! world' with priority 100, call might be blocked.
        '''
        #log_debug("IN:publish msgid: '{msgid}', msgbody: {msgbody}".format(msgid=msgid, msgbody=msgbody))
        if isinstance(msgbody, tuple):
            if not msgbody[1]:
                return False
        else:
            if not msgbody:
                return False
            else:
                msgbody = (100, msgbody)

        try:
            self.queues[msgid].put(msgbody, block=True, timeout=timeout)
        except Queue.Full as e:
            return False
        except Exception as e:
            log_warning("OUT:publish msgid: '{msgid}' queue put error:{e}".format(msgid=msgid, e=repr(e)))
            return False
        return True

    def sub(self, msgid, timeout=None):
        '''Example:
        priority, msgbody = Mailbox().sub(const.CONF_REQUEST_Q)
        '''
        #log_debug("IN:subcribe msgid: '{msgid}'".format(msgid=msgid))
        try:
            msgbody = self.queues[msgid].get(block=True, timeout=timeout)
        except Queue.Empty as e:
            msgbody = None
        except Exception as e:
            log_warning("OUT:subscrib msgid: '{msgid}' queue get error:{e}".format(msgid=msgid, e=repr(e)))
            msgbody = None
        #log_debug("OUT:subcribe msgid: '{msgid}', msgbody: {msgbody}".format(msgid=msgid, msgbody=msgbody))
        return msgbody

    def get_all(self, msgid):
        '''Example:
        msg_list = Mailbox().get_all(const.CONF_REQUEST_Q)
        msgs = [msgbody for priority, msgbody in msg_list]
        '''
        msgbody = []
        #log_debug("IN:get_all msgid: '{msgid}'".format(msgid=msgid))
        q = self.queues[msgid]
        try:
            while not q.empty():
                msgbody.append(q.get_nowait())
        except Queue.Empty as e:
            pass
        except Exception as e:
            pass
        #log_debug("OUT:get_all msgid: '{msgid}', msgbody: {msgbody}".format(msgid=msgid, msgbody=msgbody))
        return msgbody
