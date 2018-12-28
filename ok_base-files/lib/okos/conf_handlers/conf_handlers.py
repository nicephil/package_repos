from okos_tools import *


class ConfHandler(object):
    def __init__(self, mailbox, request_id, response_id, pri=1, debug=False, name='ConfHandler'):
        super(ConfHandler, self).__init__()
        self.name = name
        self.request_id = request_id
        self.response_id = response_id
        self.env = Envelope(mailbox, operate_type=response_id, pri=pri)
        self.debug = debug
    def handler(self, request):
        self.debug and log_debug('[%s] request - start -' % (self.name))
        res = self._handler(request)
        if res:
            self.env.go(res, request['cookie_id'])
            self.debug and log_debug('[%s] reply - sent out - with <%s>' % (self.name, res))
        self.debug and log_debug('[%s] request - done -' % (self.name))
    def _handler(self, request):
        log_err('You MUST implement A _handler for ConfHandler')
        raise NotImplementedError



