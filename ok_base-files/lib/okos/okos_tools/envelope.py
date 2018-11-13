import time
import json
from constant import const

class Envelope(object):
    def __init__(self, mailbox, operate_type=0, pri=200, timeout=0):
        super(Envelope, self).__init__()
        self.mailbox = mailbox
        self.pri = pri
        self.timeout = timeout
        self.msg = {
            'operate_type': operate_type,
        }

    def go(self, json_data, cookie_id=0, queue=const.STATUS_Q, pri=0):
        if not json_data:
            return
        self.msg['cookie_id'] = cookie_id
        self.msg['timestamp'] = int(time.time())
        self.msg['data'] = json.dumps(json_data)
        self.mailbox.pub(queue, (pri or self.pri, self.msg), timeout=self.timeout)

class OakmgrEnvelope(Envelope):
    def __init__(self, mailbox, operate_type, pri=1):
        super(OakmgrEnvelope, self).__init__(mailbox, operate_type=operate_type, pri=pri)
