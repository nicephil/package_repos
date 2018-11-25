import ubus
from okos_utils import log_debug, log_err, log_warning
from okos_env import ExecEnv
import copy

class UbusEnv(ExecEnv):
    def __init__(self, desc='', debug=False):
        super(UbusEnv, self).__init__('Ubus Context', desc=desc, raiseup=False, debug=debug)
        self.debug = debug
        
    def __enter__(self):
        ubus.connect()
        return super(UbusEnv, self).__enter__()
        
    def __exit__(self, exception_type, value, traceback):
        ubus.disconnect()
        return super(UbusEnv, self).__exit__(exception_type, value, traceback)

class UciSection(object):
    def __init__(self, cname, sname, data=None):
        '''
        UciSection('dhcp', 'common')
        UciSection('dhcp', 'common', {k1:v1, ...})
        '''
        super(UciSection, self).__init__()
        self._cname = cname
        self.name = sname

        if data is None:
            try:
                data = ubus.call('uci', 'get', {'config':self._cname, 'section':self.name})[0]['values']
            except Exception as e:
                data = {}
        self.type = data.setdefault('.type', '')
        self._data = {k:v for k,v in data.iteritems() if not k.startswith('.')}

    def __iter__(self):
        return self._data.__iter__()
    def iteritems(self):
        return self._data.iteritems()
    def __repr__(self):
        return self._data.__repr__()
    def __getitem__(self, key):
        return self._data.setdefault(key, '')
    def __setitem__(self, key, value):
        self._data[key] = value
        try:
            ubus.call('uci', 'set', {'config':self._cname, 'section':self.name, 'values':{key:value}})
        except Exception as e:
            log_err('Uci set <%s:%s:%s> = %s error:%s' % (self._cname, self.name, key, value, repr(e)))
    def renew(self):
        try:
            data = ubus.call('uci', 'get', {'config':self._cname, 'section':self.name})[0]['values']
        except Exception as e:
            data = {}
        if data:
            self.type = data.setdefault('.type', '')
            self._data = {k:v for k,v in data.iteritems() if not k.startswith('.')}
        return self

    def commit(self):
        try:
            ubus.call("uci", "commit", {"config":self._cname})
        except Exception as e:
            log_err('Uci commit <%s:%s> failed since %s' % (self._cname, self.name, repr(e)))

class UciConfig(object):
    def __init__(self, name):
        super(UciConfig, self).__init__()
        self._name = name
        try:
            conf = ubus.call('uci', 'get', {'config':self._name})[0]['values']
            self._data = {k:UciSection(self._name, k, s) for k,s in conf.iteritems()}
        except Exception as e:
            self._data = {}
    def __getitem__(self, key):
        return self._data.setdefault(key, UciSection(self._name, key))
    
    def __repr__(self):
        return self._data.__repr__()
    def __iter__(self):
        return self._data.__iter__()
    def iteritems(self):
        return self._data.iteritems()
    def commit(self):
        try:
            ubus.call("uci", "commit", {"config":self._name})
        except Exception as e:
            log_err('Uci commit <%s> failed since %s' % (self._name, repr(e)))

class UciStatus(object):
    def __init__(self, name):
        super(UciStatus, self).__init__()
        self.name = name
        try:
            self._data = ubus.call(self.name,'status', {})[0]
        except Exception as e:
            self._data = {}
    def __getitem__(self, key):
        return self._data.setdefault(key, '')
    def __repr__(self):
        return self._data.__repr__()
    def __iter__(self):
        return self._data.__iter__()
    def iteritems(self):
        return self._data.iteritems()
    def dump(self):
        return copy.deepcopy(self._data)

PRODUCT_INFO = UciSection('productinfo', 'productinfo')
CAPWAP_SERVER = UciSection('capwapc', 'server')


