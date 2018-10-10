#!/usr/bin/env python

import argparse, os, subprocess, re, json
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit, logcfg
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

    def doit(self, cmd):
        '''
        cmd = ['/lib/okos/bin/set_..._.sh', '33', '201'] ; shell = False
        cmd = ['/lib/okos/bin/set_..._.sh 33 201'] ; shell = True
        '''
        log_debug("[Config] Do - %s - " % (cmd))
        try:
            res = subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            log_warning("Execute %s failed!" % (e.cmd))
            return False
        except Exception as e:
            log_warning("Execute %s failed with %s!" % (cmd, type(e).__name__))
            return False
        log_debug("[Config] Do - %s - return %d" % (cmd, res))
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


