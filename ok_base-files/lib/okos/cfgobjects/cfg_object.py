#!/usr/bin/env python

import argparse, os, subprocess, re, json
from okos_utils import log_debug, log_info, log_warning, log_err, log_crit

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
    def change_op(self):
        self.action = 'CHANGE'
        self.run = self.change
        return self
    def no_op(self):
        self.action = 'NULL'
        self.run = self.noop
        return self
    def parse(self, j):
        log_debug(self.name + ' Parser interface called.')
    def add(self):
        log_debug(self.name + ' add interface called.')
        log_debug(self.data)
        #return True
    def remove(self):
        log_debug(self.name + ' remove interface called.')
        log_debug(self.data)
        #return True
    def change(self):
        log_debug(self.name + ' change interface called.')
        log_debug(self.data)
        #return True
    def noop(self):
        log_debug(self.name + ' noop interface called.')
        return True
    def pre_run(self):
        log_debug(self.name + ' pre-run interface called.')
        return True
    def post_run(self):
        log_debug(self.name + ' post-run interface called.')
        return True
    def diff(self, new, old):
        differ = self.differ
        if not differ:
            return [n.data == old[i].data and n.no_op() or n for i,n in enumerate(new)]
        else:
            news = {n.data[differ] for n in new}
            olds = {o.data[differ] for o in old}
            #change = [n.change_op() for c in news & olds for n in new if c == n.data[differ]]
            add = [n.add_op() for c in news - olds for n in new if c == n.data[differ]]
            remove = [n.remove_op() for c in olds - news for n in old if c == n.data[differ]]
            change = [n.data == o.data and n.no_op() or n.change_op()
                    for n in new for o in old if n.data[differ] == o.data[differ]]
            return remove + add + change

