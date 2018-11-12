from conf_handlers import ConfHandler
from constant import const
from okos_tools import SystemCall

class QueryWiredClients(ConfHandler):
    def __init__(self, mailbox):
        super(QueryWiredClients, self).__init__(mailbox, const.CLIENT_ONLINE_QUERY_OPT_TYPE, const.CLIENT_ONLINE_RESP_OPT_TYPE)
    def _handler(self, request):
        arpt = SystemCall().get_arp_entries()
        arpt = [{'mac': a['HW address'], 'ip': a['IP address']} for a in arpt]
        return {'clients': arpt}