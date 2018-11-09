import threading
from constant import const
from okos_tools import log_debug, log_warning, log_err, ExecEnv
from conf_handlers import ConfRequest, WebUiConf, Reboot, Diag, Upgrade, QueryWiredClients

class ConfMgr(threading.Thread):
    def __init__(self, mailbox):
        super(ConfMgr, self).__init__()
        self.name = 'ConfMgr'
        self.term = False
        self.mailbox = mailbox
        self.handlers = {}
        self._register(ConfRequest(self.mailbox))
        self._register(WebUiConf(self.mailbox))
        self._register(Reboot(self.mailbox))
        self._register(Diag(self.mailbox))
        self._register(Upgrade(self.mailbox))
        self._register(QueryWiredClients(self.mailbox))
        
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

        while not self.term:
            with ExecEnv('Conf Request', desc='Exec request from mailbox', raiseup=False, debug=True) as ctx:
                ctx.output = request = self.mailbox.sub(const.CONF_REQUEST_Q)
                request_id, cookie_id, timestamp = request['operate_type'], request['cookie_id'], request['timestamp']
                if request_id in self.handlers:
                    self.handlers[request_id].handler(request)
                else:
                    ctx.log_warning("no registered handler for {}".format(request_id))

                


