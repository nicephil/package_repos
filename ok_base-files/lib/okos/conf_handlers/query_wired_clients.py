from conf_handlers import ConfHandler
from constant import const
from okos_tools import *

class QueryWiredClients(ConfHandler):
    def __init__(self, mailbox):
        super(QueryWiredClients, self).__init__(mailbox, const.CLIENT_ONLINE_QUERY_OPT_TYPE, const.CLIENT_ONLINE_RESP_OPT_TYPE)
    def _handler(self, request):
        with ArpDb(debug=True) as arp_db:
            old = arp_db.get_all()
        
        arpt = [{'mac': a['mac'], 'ip':a['ip'], 'device':a['device'], 'vlan':dev2vlan(a['device'])} for a in old]
        return {'clients': arpt}
