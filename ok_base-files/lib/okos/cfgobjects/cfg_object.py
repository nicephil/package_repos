#!/usr/bin/env python

import argparse, os, subprocess, re, json, pprint

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
    def parse(self, j):
        print self.name + ' Parser interface called.'
    def add(self):
        print self.name + ' add interface called.'
        pprint.pprint(self.data)
    def remove(self):
        print self.name + ' remove interface called.'
        pprint.pprint(self.data)
    def change(self):
        print self.name + ' change interface called.'
        pprint.pprint(self.data)
    def pre_run(self):
        print self.name + ' pre-run interface called.'
    def post_run(self):
        print self.name + ' post-run interface called.'
    def diff(self, new, old):
        differ = self.differ
        if not differ:
            return new
        news = {n.data[differ] for n in new}
        olds = {o.data[differ] for o in old}
        if news == olds:
            return new
        else:
            change = [n.change_op() for c in news & olds for n in new if c == n.data[differ]]
            add = [n.add_op() for c in news - olds for n in new if c == n.data[differ]]
            remove = [n.remove_op() for c in olds - news for n in old if c == n.data[differ]]
            return remove + add + change

