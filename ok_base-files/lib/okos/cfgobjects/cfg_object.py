#!/usr/bin/env python

import subprocess
from okos_tools import log_debug, log_info, log_warning, log_err, log_crit, logcfg, logger
from okos_tools import ExecEnv
from constant import const
from collections import defaultdict

class CfgObj(object):
    differ = None

    def __init__(self):
        super(CfgObj, self).__init__()
        self.name = self.__class__.__name__
        self.data = {}
        self.no_op()

    def __eq__(self, other):
        return False
    def clear_action(self):
        self.action = None
        self.run = None
    def add_op(self):
        self.action = 'ADD'
        self.run = self.add
        return self
    def remove_op(self):
        self.action = 'REMOVE'
        self.run = self.remove
        return self
    def change_op(self, old=None):
        self.action = 'CHANGE'
        self.run = self.change
        self._old = old
        return self
    def no_op(self):
        self.action = 'NULL'
        self.run = self.noop
        return self

    '''
    def log(self, level, msg):
        logger(level, '[Config] ' + msg)
    def log_debug(self, msg):
        log_debug('[Config] ' + msg)
    def log_info(self, msg):
        log_info('[Config] ' + msg)
    def log_warning(self, msg):
        log_warning('[Config] ' + msg)
    def log_crit(self, msg):
        log_crit('[Config] ' + msg)
    def log_err(self, msg):
        log_err('[Config] ' + msg)
    '''

    @logcfg
    @classmethod
    def parse(cls, j):
        raise NotImplementedError

    @logcfg
    def add(self):
        raise NotImplementedError

    @logcfg
    def remove(self):
        raise NotImplementedError

    @logcfg
    def change(self):
        raise NotImplementedError

    @logcfg
    def noop(self):
        return True

    @classmethod
    def pre_run(cls, cargo=None, goods=None):
        return True

    @classmethod
    def post_run(cls, cargo=None, goods=None):
        return True

    @staticmethod
    def add_service(service, cargo):
        if cargo is not None:
            cargo['services'].add(service)

    def check_para(self, fmt, entry):
        for k, func in fmt.iteritems():
            if callable(func):
                res = func(entry[k], obj_name=k)
                if not res:
                    return False
        return True

    @staticmethod
    def doit(cmd, comment='', path=const.CONFIG_BIN_DIR, shell=False):
        '''
        cmd = ['/lib/okos/bin/set_..._.sh', '33', '201'] ; shell = False
        cmd = ['/lib/okos/bin/set_..._.sh 33 201'] ; shell = True
        '''
        comment and log_debug('[Config] {comment}'.format(comment=comment))
        log_debug("[Config] Do - {cmd} - ".format(cmd=cmd))
        try:
            cmd = map(str, cmd)
            if not cmd[0].startswith('/'):
                cmd[0] = path + cmd[0]
            rc = subprocess.check_call(cmd, shell=shell)
        except subprocess.CalledProcessError as e:
            log_warning("[Config] Do - {cmd} - return failure <{rc}> : {output}".format(cmd=e.cmd, rc=e.returncode, output=e.output))
            res = False
        except Exception as e:
            log_warning("[Config] Do - {cmd} - failed with {expt}!".format(cmd=cmd, expt=type(e).__name__))
            res = False
        else:
            log_debug("[Config] Do - {cmd} - done <{rc}>".format(cmd=cmd, rc=rc))
            res = bool(rc == 0)
        return res

    @classmethod
    @logcfg
    def diff(cls, new, old):
        '''
        :INPUT:
        new = [cfg_object1, ...];
        old = [cfg_object1, .....];
        '''
        differ = cls.differ
        log_debug("{cname}' differ is {differ}".format(cname=cls.__name__, differ=differ))
        if not differ:
            added   = [i.add_op() for i in new[len(old):]]
            removed = [i.remove_op() for i in old[len(new):]]
            changed = [n.change_op(old[i]) for i,n in enumerate(new[:len(old)]) if n.data != old[i].data]
            res = removed + changed + added
            log_debug('result: {rs}'.format(rs=[(r.action, i) for i,r in enumerate(res)]))
        else:
            new = {i.data[differ]:i for i in new}
            old = {i.data[differ]:i for i in old}
            new_ids = set(new.keys())           # set (id1, id2, ..., idm)
            old_ids = set(old.keys())           # set (idn, idn+1, ....., idx)
            added   = [new[i].add_op() for i in new_ids - old_ids]
            removed = [old[i].remove_op() for i in old_ids - new_ids]
            changed = [new[i].change_op(old[i]) for i in new_ids & old_ids if new[i].data != old[i].data]
            res = removed + changed + added
            log_debug('result: {rs}'.format(rs=[(r.action, r.data[differ]) for r in res]))
        return res
    
    def _check_ipaddr_(self, input):
        p_ipaddr = const.FMT_PATTERN['ipaddr']
        result = p_ipaddr.match(input)
        if not result:
            return False, 'IP address format error'
        ip = result.groups()
        ip = map(int, ip)
        ips = filter(lambda i: bool(i >= 0 and i < 256), ip)
        if len(ips) != len(ip):
            return False, 'IP address format error'
        return True, input

    def _check_zone_(self, input):
        return bool(input in const.CONFIG_SECURITY_ZONE), input
    
    def _check_entry_id_(self, input):
        p_id = const.FMT_PATTERN['entry_id']
        return p_id.match(input), input
    def _check_simple_id_(self, input):
        p_id = const.FMT_PATTERN['simple_id']
        return p_id.match(input), input
    def _check_number_(self, input):
        p = const.FMT_PATTERN['number']
        return p.match(input), input

    def _check_sock_port_(self, input):
        p = const.FMT_PATTERN['socket_port_range']
        m = p.match(str(input))
        if not m:
            return False, 'port range format error'
        m = m.groups()
        start, end = int(m[0]), m[2] and int(m[2]) or m[2]
        if end is not None:
            if start >= 65536:
                return False, 'port number error:(0 < port < 65536)'
            if end <= start:
                return False, 'port range error:(start < end)'
        if start == 0:
            return False, 'port range error:(0 < port < 65536)'
        return True, '%d:%d' % (start, end) if end else '%d' % (start)

    def _check_mac_(self, input):
        p = const.FMT_PATTERN['mac']
        m = p.match(str(input))
        if not m:
            return False, 'MAC address format error'
        mac = ':'.join(m.groups())
        return True, mac.lower()

class ParameterChecker(object):
    '''
    {
        'item1': {'checker': func_check, 'default': None, 'value': xxx },
    }
    '''
    def __init__(self, src):
        self.src = src
        self.fmt = {}
    def dump(self):
        for k, entry in self.fmt.iteritems():
            if callable(entry['checker']):
                res, entry['value'] = entry['checker'](entry['value'])
                if not res:
                    return False
        return True
    def __getitem__(self, index):
        return self.fmt[index]['value']
    def __setitem__(self, index, checker):
        func, default = checker[0], checker[1]
        entry = self.fmt[index] = {'checker': func, 'default': default}
        if default is None:
            entry['value'] = self.src[index]
        else:
            entry['value'] = self.src.setdefault(index, default)
        if callable(entry['checker']):
            res, data = entry['checker'](entry['value'])
            if not res:
                log_warning('[Parameter Checking] %s failed (%s) - %s -' % (index, entry['value'], data))
                raise ExceptionConfigError('ParameterChecker', 'check %s failed' % (index), entry['value'])
            else:
                log_debug('[Parameter Checking] for [{idx}]:>[{d}]'.format(idx=index, d=data))
                entry['value'] = data
            


class ConfigInputEnv(ExecEnv):
    def __init__(self, cfg, desc='', debug=False):
        super(ConfigInputEnv, self).__init__('Config Input', cfg, desc, debug=debug)

class ConfigParseEnv(ExecEnv):
    def __init__(self, json, desc='', debug=False):
        super(ConfigParseEnv, self).__init__('Config Parse', json, desc, debug=debug)

class ConfigParaCheckEnv(ExecEnv):
    def __init__(self, para, desc='', debug=False):
        super(ConfigParaCheckEnv, self).__init__('Config Check', para, desc, debug=debug)
    def __exit__(self, exception_type, value, traceback):
        if exception_type == 'ExceptionConfigParaError':
            log_warning('[%s] %s - faied (%s) -' % (self.prefix, self.desc, value))
            return True
        return super(ConfigParaCheckEnv, self).__exit__(exception_type, value, traceback)

class ExceptionConfigError(Exception):
    def __init__(self, process, reason='', data=None):
        super(ExceptionConfigError, self).__init__()
        self.process = process
        self.reason = reason
        self.data = data
    def __str__(self):
        return "[Config %s] failed since '%s' with (%s)" % (self.process, self.reason, str(self.data))

class ExceptionConfigParaError(ExceptionConfigError):
    def __init__(self, obj, param, reason, data=None):
        super(ExceptionConfigParaError, self).__init__('Parameter Checking', reason, data)
        self.obj = obj
        self.param = param
    def __str__(self):
        return "[Config %s - %s:%s] failed since '%s' with (%s)" % (self.process, self.obj, self.param, self.reason, str(self.data))


