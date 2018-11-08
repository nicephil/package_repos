import threading
from constant import const
from okos_logger import log_debug, log_warning, log_err
from conf_handlers import ConfRequest, WebUiConf, Reboot, Diag, Upgrade


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
        
        self.timers = [
        ]
    def _register(self, handler):
        self.handlers[handler.request_id] = handler
    
    def run(self):
        map(lambda x: x.start(), self.timers)

        while not self.term:
            try:
                request = self.mailbox.sub(const.CONF_REQUEST_Q)
                log_debug('request:{request}'.format(request=request))
                request_id = request['operate_type']
                if request_id in self.handlers:
                    self.handlers[request_id].handler(request)
                else:
                    log_warning("no register handler for {}".format(request))
            except Exception,e:
                log_warning("process_data:{}, {}".format(request, e))
                raise

