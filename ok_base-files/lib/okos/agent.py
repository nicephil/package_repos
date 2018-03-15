#!/usr/bin/python

import sys, os, time, atexit
from signal import SIGTERM
import urllib2, json, random
from subprocess import Popen,PIPE
import re, logging
from threading import Timer

class Daemon(object):
        """
        A generic daemon class.

        Usage: subclass the Daemon class and override the run() method
        """
        def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
                self.stdin = stdin
                self.stdout = stdout
                self.stderr = stderr
                self.pidfile = pidfile
                self.is_daemon = True

        def daemonize(self):
                """
                do the UNIX double-fork magic, see Stevens' "Advanced
                Programming in the UNIX Environment" for details (ISBN 0201563177)
                http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
                """
                try:
                        pid = os.fork()
                        if pid > 0:
                                # exit first parent
                                sys.exit(0)
                except OSError, e:
                        sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
                        sys.exit(1)

                # decouple from parent environment
                os.chdir("/")
                os.setsid()
                os.umask(0)

                # do second fork
                try:
                        pid = os.fork()
                        if pid > 0:
                                # exit from second parent
                                sys.exit(0)
                except OSError, e:
                        sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
                        sys.exit(1)

                # redirect standard file descriptors
                sys.stdout.flush()
                sys.stderr.flush()
                si = file(self.stdin, 'r')
                so = file(self.stdout, 'a+')
                se = file(self.stderr, 'a+', 0)
                os.dup2(si.fileno(), sys.stdin.fileno())
                os.dup2(so.fileno(), sys.stdout.fileno())
                os.dup2(se.fileno(), sys.stderr.fileno())

                # write pidfile
                atexit.register(self.delpid)
                pid = str(os.getpid())
                file(self.pidfile,'w+').write("%s\n" % pid)

        def delpid(self):
                os.remove(self.pidfile)

        def start(self,doit=True):
                """
                Start the daemon
                """
                # Check for a pidfile to see if the daemon already runs
                try:
                        pf = file(self.pidfile,'r')
                        pid = int(pf.read().strip())
                        pf.close()
                except IOError:
                        pid = None

                if pid:
                        message = "pidfile %s already exist. Daemon already running?\n"
                        sys.stderr.write(message % self.pidfile)
                        sys.exit(1)

                # Start the daemon
                if doit:
                    self.is_daemon = True
                    self.daemonize()
                else:
                    self.is_daemon = False
                self.run()

        def getpid (self):
                try:
                        pf = file(self.pidfile,'r')
                        pid = int(pf.read().strip())
                        pf.close()
                except IOError:
                        pid = None
                return pid

        def status (self):
                pid = self.getpid ()
                if not pid:
                        sys.stderr.write ("Daemon not running\n")
                else:
                        sys.stderr.write ("Daemon running as %d\n" % pid)

        def stop(self):
                """
                Stop the daemon
                """
                pid = self.getpid ()

                if not pid:
                        message = "pidfile %s does not exist. Daemon not running?\n"
                        sys.stderr.write(message % self.pidfile)
                        return # not an error in a restart

                # Try killing the daemon process
                try:
                        while 1:
                                os.kill(pid, SIGTERM)
                                time.sleep(0.1)
                except OSError, err:
                        err = str(err)
                        if err.find("No such process") > 0:
                                if os.path.exists(self.pidfile):
                                        os.remove(self.pidfile)
                        else:
                                print str(err)
                                sys.exit(1)

        def restart(self):
                """
                Restart the daemon
                """
                self.stop()
                self.start()

        def run(self):
                """
                You should override this method when you subclass Daemon. It will be called after the process has been
                daemonized by start() or restart().
                """


# https://www.blog.pythonlibrary.org/2016/05/17/python-101-how-to-timeout-a-subprocess/
class Agent (Daemon):
    def __init__ (self, refetch_interval=600, nextcmd_interval=3600):
        self.interval= {
                        'jitter': 0.1,
                        'refetch': refetch_interval,
                        'nextcmd': nextcmd_interval
                       }
        self.pidfile = "/tmp/agentagent.pid"
        self.url = "http://54.187.17.14:8102/clientcenter/v0/gohome"
        self.next_tic = time.time()
        self.now = time.time()
        self.current_process = None
        self.mac_re = re.compile('([a-fA-F0-9]{2}[:|\-]?){6}')
        self.macaddr = ""
        self.get_mac()
        self.lastcmd = { 'cmd': None,            # clear last cmd state
                         'exit_code': 0,
                         'stdout': "",
                         'stderr': "",
                         'exception': "",
                         'token': None,
                         'note': ""}
        self.tod = 0
        super(Agent, self).__init__(self.pidfile)   # init base class

    def get_mac (self):
        p = Popen(["uci", "get", "productinfo.productinfo.mac"], stdout=PIPE,stderr=PIPE)
        mac, err = p.communicate();
        self.macaddr = mac.strip()
        if not self.mac_re.search(self.macaddr):
            logging.error ("Panic, can't get mac address")
            sys.exit(3)

    def random_tic (self, what):  # return a randem int around <what>
        return random.randint (int(self.interval[what]*(1-self.interval['jitter'])), int(self.interval[what]*(1+self.interval['jitter'])))
    def set_next_tic (self, delta):
        self.now = time.time()
        self.next_tic = self.now + delta
    def hibernate (self):
        self.now = time.time()
        sleeptime = self.tod
        if self.next_tic > self.now and self.tod == 0:
            sleeptime = self.next_tic - self.now
        logging.debug ("hibernate for %d second", sleeptime)
        time.sleep (sleeptime)
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
                self.tod = data['tod']
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
            self.lastcmd['note'] = ""
            self.tod = 0
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
                self.lastcmd['exit_code'] = self.current_process.returncode
                logging.debug ("cmd exit: %d", self.lastcmd['exit_code'])
                timer.cancel()

            logging.debug ("lastcmd result: %s", str(self.lastcmd))
            self.set_next_tic (self.random_tic ('nextcmd'))




if __name__ == "__main__":

    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            logging.basicConfig(format='%(asctime)s %(levelname)s %(filename)s:%(lineno)s %(message)s', level=logging.ERROR)
            agent = Agent()
            agent.start()
        if 'START' == sys.argv[1]:
            logging.basicConfig(format='%(asctime)s %(levelname)s %(filename)s:%(lineno)s %(message)s', level=logging.DEBUG)
            agent = Agent( refetch_interval=10, nextcmd_interval=90)
            agent.start(False)
        elif 'stop' == sys.argv[1]:
            agent = Agent()
            agent.stop()
        elif 'restart' == sys.argv[1]:
            agent = Agent()
            agent.restart()
        elif 'status' == sys.argv[1]:
            agent = Agent()
            agent.status ()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s START|start|stop|restart" % sys.argv[0]
        sys.exit(2)
