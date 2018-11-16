import threading
from constant import const
from okos_tools import *
from conf_handlers import *
import time

class ConfMgr(threading.Thread):
    def __init__(self, mailbox, debug=False):
        super(ConfMgr, self).__init__()
        self.debug = debug
        self.name = 'ConfMgr'
        self.term = False
        self.mailbox = mailbox
        self.handlers = {}
        self._register(ConfRequest(self.mailbox))
        self._register(WebUiConf(self.mailbox))
        self._register(Reboot(self.mailbox))
        self._register(Diag(self.mailbox))
        self._register(Upgrade(self.mailbox))
        self._register(QueryWiredClients(self.mailbox, debug=True))
        
        self.timers = [
        ]
    def _register(self, handler):
        self.handlers[handler.request_id] = handler
    
    def run(self):
        '''
        {
            "mac" : "000C2932A423",
            "delay" : 10,
            "list" : [
                {
                    "operate_type" : 3102,
                    "cookie_id" : 1234,
                    "timestamp" : 2222222,
                    "data" : "{\"url\" : \"http://image.oakridge.vip/images/x86_gw/sysloader/v2.433.2_bin.app\", \"timeout\" : 60}"
                }
            ],
            'errorcode': 1002,
        }
        '''
        map(lambda x: x.start(), self.timers)

        while_loop = lambda : ((not self.term) and self._round()) or while_loop
        #while_loop()
        while not self.term:
            self._round()

    def _round(self):
        with ExecEnv('Conf Request', desc='Exec request from mailbox', raiseup=False, debug=self.debug) as ctx:
            request = self.mailbox.sub(const.CONF_REQUEST_Q)
            if not request:
                time.sleep(10)
                ctx.log_err('subscribe message from CONF_REQUEST_Q failed!\n\n')
                return
            ctx.output = request = request[1]
            request_id, _cookie_id, _timestamp = request['operate_type'], request['cookie_id'], request['timestamp']
            if request_id in self.handlers:
                self.handlers[request_id].handler(request)
            else:
                ctx.log_warning("no registered handler for {}".format(request_id))

                


