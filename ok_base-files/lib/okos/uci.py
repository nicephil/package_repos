import ubus

class UciSection(object):
    def __init__(self, cname=None, sname=None, oname=None):
        '''
        UciSection(name = ('dhcp', 'common'))
        '''
        super(UciSection, self).__init__()
        if cname and sname:
            self.name = sname
            if not oname:
                section = ubus.call('uci', 'get', {'config':cname, 'section':sname})[0]['values']
                self._section(section, cname)
            else:
                self._cname = cname
                self.name = sname
                self._data = {oname: ubus.call('uci', 'get', {'config':self._cname, 'section':self.name, 'option':oname})[0]['value']}
            

    def _section(self, section, conf_name):
        self._cname = conf_name
        self.name = section['.name']
        self.type = section['.type']
        self.anonymous = section['.anonymous']
        self.index = section.setdefault('.index', 0)
        self._data = {k:v for k,v in section.iteritems() if not k.startswith('.')}
        return self

    def __iter__(self):
        return self._data.__iter__()
    def iteritems(self):
        return self._data.iteritems()
    def __repr__(self):
        return self._data.__repr__()
    def __getitem__(self, key):
        if key in self._data:
            return self._data
        else:
            try:
                q = ubus.call('uci', 'get', {'config':self._cname, 'section':self.name, 'option':key})[0]['value']
            except Exception as e:
                q = ''
            self._data[key] = q
        return self._data[key]
    def __setitem__(self, key, value):
        self._data[key] = value
        ubus.call('uci', 'set', {'config':self._cname, 'section':self.name, 'values':{key:value}})
    def commit(self):
        ubus.call("uci", "commit", {"config":self._cname})

class UciConfig(object):
    def __init__(self, name):
        super(UciConfig, self).__init__()
        self._name = name
        conf = ubus.call('uci', 'get', {'config':self._name})[0]['values']
        self._data = {k:UciSection()._section(s, self._name) for k,s in conf.iteritems()}
    def __getitem__(self, key):
        return self._data.setdefault(key, UciSection(self._name, key))
    
    def __repr__(self):
        return self._data.__repr__()
    def __iter__(self):
        return self._data.__iter__()
    def iteritems(self):
        return self._data.iteritems()
    def commit(self):
        ubus.call("uci", "commit", {"config":self._name})