#!/usr/bin/env python

import argparse, os, subprocess, re, json
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit, logcfg, logger, ExecEnv
from constant import const

class CfgObj(object):
    def __init__(self, differ=None):
        super(CfgObj, self).__init__()
        self.action = None
        self.name = self.__class__.__name__
        self.differ = differ
        self.data = {}
        self.run = None
        self.change_op()
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

    @logcfg
    def parse(self, j):
        pass

    @logcfg
    def add(self):
        log_debug(self.data)
        #return True

    @logcfg
    def remove(self):
        log_debug(self.data)
        #return True

    @logcfg
    def change(self):
        log_debug(self.data)
        #return True

    @logcfg
    def noop(self):
        return True

    @logcfg
    def pre_run(self):
        return True

    @logcfg
    def post_run(self):
        return True

    def check_para(self, fmt, entry):
        for k, func in fmt.iteritems():
            if callable(func):
                res = func(entry[k], obj_name=k)
                if not res:
                    return False
        return True

    def doit(self, cmd, comment=''):
        '''
        cmd = ['/lib/okos/bin/set_..._.sh', '33', '201'] ; shell = False
        cmd = ['/lib/okos/bin/set_..._.sh 33 201'] ; shell = True
        '''
        if comment:
            self.log_debug(comment)
        self.log_debug("Do - %s - " % (cmd))
        try:
            cmd = [str(c) for c in cmd]
            res = subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            self.log_warning("Execute %s failed!" % (e.cmd))
            return False
        except Exception as e:
            self.log_warning("Execute %s failed with %s!" % (cmd, type(e).__name__))
            return False
        self.log_debug("Do - %s - return %d" % (cmd, res))
        return res == 0 and True or False

    @logcfg
    def diff(self, new, old):
        differ = self.differ
        if not differ:
            add = [i.add_op() for i in new[len(old):]]
            remove = [i.remove_op() for i in old[len(new):]]
            change = [n.data == old[i].data and n.no_op() or n.change_op(old[i]) for i,n in enumerate(new[:len(old)])]
            return remove + add + change
            #return [n.data == old[i].data and n.no_op() or n.change_op(old[i]) for i,n in enumerate(new)]
        else:
            news = {n.data[differ] for n in new}
            olds = {o.data[differ] for o in old}
            #change = [n.change_op() for c in news & olds for n in new if c == n.data[differ]]
            add = [n.add_op() for c in news - olds for n in new if c == n.data[differ]]
            remove = [n.remove_op() for c in olds - news for n in old if c == n.data[differ]]
            change = [n.data == o.data and n.no_op() or n.change_op(o)
                    for n in new for o in old if n.data[differ] == o.data[differ]]
            return remove + add + change

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
                res, entry['value'] = entry['checker'](entry['value'], obj_name=k)
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
            res, data = entry['checker'](entry['value'], obj_name=index)
            if not res:
                raise ExceptionConfigError('ParameterChecker', 'check %s failed' % (index), entry['value'])
            else:
                entry['value'] = data
            


class ConfigInputEnv(ExecEnv):
    def __init__(self, cfg, desc=''):
        super(ConfigInputEnv, self).__init__('Config Input', cfg, desc)

class ConfigParseEnv(ExecEnv):
    def __init__(self, json, desc=''):
        super(ConfigParseEnv, self).__init__('Config Parse', json, desc)

class ConfigParaCheckEnv(ExecEnv):
    def __init__(self, para, desc=''):
        super(ConfigParaCheckEnv, self).__init__('Config Check', para, desc)
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


