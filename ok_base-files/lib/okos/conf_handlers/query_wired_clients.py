from conf_handlers import ConfHandler
from constant import const
from okos_tools import *

class QueryWiredClients(ConfHandler):
    '''
{
    "mac" : "000C2932A423",
    "delay" : 10,
    "list" : [
        {
            "operate_type" : 2016,
            "cookie_id" : 1234,
            "timestamp" : 2222222,
            "data" : "{\"timeout\" : 60}"
        }
    ],
    "errorcode": 1002
}
    '''
    def __init__(self, mailbox, debug=False):
        super(QueryWiredClients, self).__init__(mailbox, \
            const.CLIENT_ONLINE_QUERY_OPT_TYPE, const.CLIENT_ONLINE_RESP_OPT_TYPE, \
            debug=debug, name='Query Wired Clients')
        self.debug = debug
        
    def _handler(self, request):
        with ArpDb(debug=self.debug) as arp_db:
            all = arp_db.get_all(timestamp=True)
        
        arpt = map(lambda x: clients_output_fmt(x), all)
        return {'clients': arpt}
