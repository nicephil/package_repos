#!/usr/bin/python

import sys, os, time, atexit
from signal import SIGTERM
import urllib2, json, random
from subprocess import Popen,PIPE
import re, logging
from threading import Timer, Thread
from okos_utils import get_mac

logging.basicConfig(format='%(asctime)s %(levelname)s %(filename)s:%(lineno)s %(message)s', level=logging.DEBUG)

# https://www.blog.pythonlibrary.org/2016/05/17/python-101-how-to-timeout-a-subprocess/
class Agent (Thread):
    __slots__ = ('interval', 'url', 'next_tic', 'now', 'current_process', 'mac_re', 'macaddr', 'lastcmd')

    def __init__ (self, refetch_interval=600, nextcmd_interval=3600):
        Thread.__init__(self)
        self.interval= {
                        'jitter': 0.1,
                        'refetch': refetch_interval,
                        'nextcmd': nextcmd_interval
                       }
        self.url = "http://clientcenter.oakridge.io:8102/clientcenter/v0/gohome"
        self.next_tic = time.time()
        self.name = "Agent"
        self.now = time.time()
        self.current_process = None
        self.mac_re = re.compile('([a-fA-F0-9]{2}[:|\-]?){6}')
        self.macaddr = get_mac('br-lan1')
        self.lastcmd = { 'cmd': None,            # clear last cmd state
                         'exit_code': 0,
                         'stdout': "",
                         'stderr': "",
                         'exception': "",
                         'token': None,
                         'runtime': 0,
                         'note': ""}

    def random_tic (self, what):  # return a randem int around <what>
        return random.randint (int(self.interval[what]*(1-self.interval['jitter'])), int(self.interval[what]*(1+self.interval['jitter'])))

    def set_next_tic (self, delta):
        self.now = time.time()
        self.next_tic = self.now + delta

    def hibernate (self):
        self.now = time.time()
        if self.next_tic > self.now:
            logging.debug ("hibernate for %d second", self.next_tic - self.now)
            time.sleep (self.next_tic - self.now)

    def timer_action (self):
        if self.current_process:
            logging.debug ("timer fired for process %d", self.current_process.pid)
            os.killpg(os.getpgid(self.current_process.pid), SIGTERM)
            self.lastcmd['note'] = "killed after %s sec" % (self.interval['nextcmd'])
        else:
            logging.debug ("timer fired with None process")

    def run(self):
        while True:
            self.hibernate ()
            try:    # get instruction
                last = json.dumps(self.lastcmd)
                clen = len(last)
                url = self.url+"?key=1&device="+self.macaddr
                req = urllib2.Request (url, last, {'Content-Type': 'application/json', 'Content-Length': clen})
                response = urllib2.urlopen(req)
                data= json.loads(response.read())
                cmd = data['cmd']['shell']
                self.interval['nextcmd'] = data['tod']
                if 'token' in data:
                    self.lastcmd['token'] = data['token']
                else:
                    self.lastcmd['token'] = None
            except Exception as e:
                logging.error ("%s" % (e))
                self.set_next_tic (self.random_tic ('refetch'))
                continue

            self.lastcmd['cmd'] = cmd
            self.lastcmd['exit_code'] = 0
            self.lastcmd['stdout'] = ""
            self.lastcmd['stderr'] = ""
            self.lastcmd['exception'] = ""
            self.lastcmd['runtime'] = time.time()
            self.lastcmd['note'] = ""
            logging.debug("<%s> ...", cmd)

            try:
                self.current_process = Popen(cmd, stdout=PIPE,stderr=PIPE,shell=True,cwd='/tmp',preexec_fn=os.setsid) # so that we can kill the process group
                timer = Timer (self.interval['nextcmd'], self.timer_action)
                timer.start()
                logging.debug ("%d will automcatically be killed in %d second", self.current_process.pid, self.interval['nextcmd'])
                self.lastcmd['stdout'], self.lastcmd['stderr'] = self.current_process.communicate()
            except Exception as e:
                self.lastcmd['exception'] = str(e)
                logging.debug ("%s", self.lastcmd['exception'])
            finally:
                self.lastcmd['runtime'] = time.time() - self.lastcmd['runtime']
                self.lastcmd['exit_code'] = self.current_process.returncode
                logging.debug ("cmd exit: %d", self.lastcmd['exit_code'])
                timer.cancel()

            logging.debug ("lastcmd result: %s", str(self.lastcmd))
            if self.lastcmd['note'] != "":
                self.set_next_tic (0)
            else:
                self.set_next_tic (self.interval['nextcmd'] - self.lastcmd['runtime'])

