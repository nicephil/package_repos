import fcntl
from subprocess import Popen, PIPE
import threading

import requests
import json
import os
import sys
import time
import syslog
import ubus
import functools
import vici
import subprocess
import re
import socket

from constant import const

def okos_system_log_info(msg):
	syslog.openlog("01-SYSTEM-LOG", syslog.LOG_NDELAY, syslog.LOG_USER)
	syslog.syslog(syslog.LOG_INFO, msg)
	syslog.closelog()

def okos_system_log_warn(msg):
	syslog.openlog("01-SYSTEM-LOG", syslog.LOG_NDELAY, syslog.LOG_USER)
	syslog.syslog(syslog.LOG_WARNING, msg)
	syslog.closelog()

def okos_system_log_err(msg):
	syslog.openlog("01-SYSTEM-LOG", syslog.LOG_NDELAY, syslog.LOG_USER)
	syslog.syslog(syslog.LOG_ERR, msg)
	syslog.closelog()

def log_debug(msg):
    syslog.syslog(syslog.LOG_DEBUG, "[{threadName}]:{msg}".format(threadName=threading.currentThread().getName(), msg=msg))

def log_info(msg):
    syslog.syslog(syslog.LOG_INFO, "[{threadName}]:{msg}".format(threadName=threading.currentThread().getName(), msg=msg))

def log_warning(msg):
    syslog.syslog(syslog.LOG_WARNING, "[{threadName}]:{msg}".format(threadName=threading.currentThread().getName(), msg=msg))

def log_err(msg):
    syslog.syslog(syslog.LOG_ERR, "[{threadName}]:{msg}".format(threadName=threading.currentThread().getName(), msg=msg))

def log_crit(msg):
    syslog.syslog(syslog.LOG_CRIT, "[{threadName}]:{msg}".format(threadName=threading.currentThread().getName(), msg=msg))

LOGGER = {
        'debug': log_debug,
        'info': log_info,
        'warning': log_warning,
        'err': log_err,
        'crit': log_crit,
        }
def logger(level, msg):
    if level in LOGGER:
        LOGGER[level](msg)

def logcfg(func):
    def wrapper(*args, **kwargs):
        log_debug("[Config] Start to <%s:%s>:" % (args[0].__class__.__name__, func.__name__))
        res = func(*args, **kwargs)
        log_debug("[Config] <%s:%s> is done." % (args[0].__class__.__name__, func.__name__))
        #log_debug("<%s> is done." % func.__name__)
        return res
    return wrapper

def logit(func):
    def wrapper(*args, **kwargs):
        log_debug("Start to <%s:%s>:" % (args[0].__class__.__name__, func.__name__))
        res = func(*args, **kwargs)
        log_debug("<%s:%s> is done." % (args[0].__class__.__name__, func.__name__))
        #log_debug("<%s> is done." % func.__name__)
        return res
    return wrapper

def logchecker(check_name):
    def logger(func):
        def wrapper(*args, **kwargs):
            obj_name = 'obj_name' in kwargs and kwargs['obj_name'] or func.__name__
            log_debug('[%s Parameter Checking] for [%s]:>' % (check_name, obj_name))
            res, value = func(*args, **kwargs)
            if not res:
                log_warning('[%s Parameter Checking] %s failed (%s) - %s -' % (check_name, obj_name, args[1], value))
                return False, None
            else:
                return True, value
        return wrapper
    return logger

config_conf_file = ''.join([const.CONFIG_DIR, const.CONFIG_CONF_FILE])

def repeat_timer(interval=5, name='StatusTimer'):
    '''
    make the function called repeatedly.
    '''
    def decorator_repeat(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            this = args[0]
            res = func(*args, **kwargs)
            this.add_timer(name, interval, wrapper)
            return res
        return wrapper
    return decorator_repeat

class RepeatedTimer(object):
    def __init__(self, name, interval, func):
        super(RepeatedTimer, self).__init__()
        self.name = name
        self.interval = interval
        self.func = func
        self.timer = threading.Timer(interval, self.repeat(func, interval))
        self.timer.setName(name)
        log_debug('Timer is created')
    def start(self):
        self.timer.start()
        log_debug('Timer is kicked off')
    def repeat(self, func, interval):
        def wrapper(*args, **kwargs):
            log_debug('Timer start to execute:')
            res = func(*args, **kwargs)
            self.timer = threading.Timer(interval, self.repeat(func, interval))
            self.timer.setName(self.name)
            self.start()
            return res
        return wrapper
            
class ReportTimer(object):
    def __init__(self, name, interval, func, mailbox, operate_type):
        super(ReportTimer, self).__init__()
        self.name = name
        self.interval = interval
        self.func = func
        self.timer = threading.Timer(interval, self.repeat(func, interval))
        self.timer.setName(name)
        self.env = OakmgrEnvelope(mailbox, operate_type)
        log_debug('Timer is created')
    def start(self):
        self.timer.start()
        log_debug('Timer is kicked off')
    def repeat(self, func, interval):
        def wrapper(*args, **kwargs):
            log_debug('Timer start to execute:')
            res = func(*args, **kwargs)
            if res:
                self.env.send(res)
            self.timer = threading.Timer(interval, self.repeat(func, interval))
            self.timer.setName(self.name)
            self.start()
            return res
        return wrapper

def set_capwapc(mas_server):
    """" set capwapc """
    try:
        ubus.call("uci", "set", {"config":"capwapc","section":"server", "values":{"mas_server":mas_server}})
        #_, _, localip = SystemCall().localip2target(mas_server)
        #ubus.call("uci", "set", {"config":"capwapc","section":"server", "values":{"local_ip":localip}})
        ubus.call("uci", "commit", {"config":"capwapc"})
    except Exception, e:
        log_warning('set_capwapc get exception {}'.format(repr(e)))
        return False
    return True

def get_capwapc():
    """" get capwapc """
    capwapc_data={}
    try:
        value=ubus.call("uci", "get", {"config":"capwapc","section":"server"})
        capwapc_data=value[0]['values']
    except Exception, e:
        log_warning('get_capwapc get exception {}'.format(repr(e)))
        capwapc_data={}
    return capwapc_data

def get_productinfo():
    """" get productinfo """
    try:
        value=ubus.call("uci", "get", {"config":"productinfo","section":"productinfo"})
        productinfo_data=value[0]['values']
    except Exception, e:
        log_warning('get_productinfo get exception {}'.format(repr(e)))
        productinfo_data={}
    return productinfo_data

def get_whole_conf_path():
    global config_conf_file
    return config_conf_file

def get_whole_conf_bak_path():
    global config_conf_file
    return "{}_bak".format(config_conf_file)

def set_whole_confinfo(str):
    with open(config_conf_file, 'rw+', 0) as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        with open("{}_bak".format(config_conf_file), 'w+', 0) as ff:
            ff.truncate()
            ff.write(f.read())
            ff.flush()
        f.seek(0,0)
        f.truncate()
        f.write(str)
        f.flush()
    confinfo_data = json.loads(str, encoding='utf-8')
    return confinfo_data

def rollback_whole_confinfo():
    with open(config_conf_file, 'w+', 0) as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        with open("{}_bak".format(config_conf_file), 'r') as ff:
            str = ff.read()
        f.truncate()
        f.write(str)
        f.flush()
    confinfo_data = json.loads(str, encoding='utf-8')
    return confinfo_data

def get_whole_confinfo():
    with open(config_conf_file, 'r') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        str = f.read()
    confinfo_data = json.loads(str, encoding='utf-8')
    return confinfo_data

def get_ddns_status(provider):
    try:
        cmd = "{} {}".format(const.OKOS_DDNS_STATUS_SCRIPT, provider)
        pid = Popen(cmd, stdout=PIPE, shell=True)
        s = pid.communicate()[0]
        s.strip('\n')
        ddns_status_data = json.loads(s, 'utf-8')
    except Exception, e:
        log_warning('get_ddns_status get exception {}'.format(repr(e)))
        ddns_status_data = None
    return ddns_status_data

def get_file_md5sum(file_name):
    """" fetch productinfo """
    try:
        cmd = "md5sum {file_name} | awk '{{print $1}}' 2>/dev/null".format(file_name=file_name)
        pid = Popen(cmd, stdout=PIPE, shell=True)
        s = pid.communicate()[0]
        md5sum = s.strip('\n')
    except Exception, e:
        log_warning('get_file_md5sum get exception {}'.format(repr(e)))
        md5sum = ""
    return md5sum

def get_redirector_key(salt, mac):
    """" fetch redirector key """
    try:
        cmd = "echo -n \"{_salt}{_mac}\" | md5sum | awk '{{print $1}}'".format(_salt=salt, _mac=mac)
        pid = Popen(cmd, stdout=PIPE, shell=True)
        s = pid.communicate()[0]
        key = s.strip('\n')
    except Exception, e:
        log_warning('get_redirector_key get exception {}'.format(repr(e)))
        key = ""
    return key


def post_url(url, param_data=None, json_data=None, files=None):
    log_debug('post to {url}'.format(url=url))
    log_debug('parameters :{param_data}'.format(param_data=param_data))
    log_debug('json body :{json_data}'.format(json_data=json_data))

    for i in range(1,4):
        try:
            response = requests.post(url, params=param_data, json=json_data, files=files, timeout=5)
            if response.status_code == 200:
                data = response.json()
                log_debug('response:status:{status},json:{json}'.format(status=response.status_code, json=data))
                return data
            else:
                log_warning('response:status:{status},response:{response}'.format(status=response.status_code, response=response))
        except Exception, e:
            time.sleep(1)
            log_warning("requests err {}, time:{}".format(repr(e), i))
            continue
    return {}


def get_url(url, param_data=None, json_data=None):
    log_debug('url:{url}'.format(url=url))
    log_debug('param_data:{param_data}'.format(param_data=param_data))
    log_debug('json_data:{json_data}'.format(json_data=json_data))
    i = 0
    while i < 3:
        try:
            response = requests.get(url, params=param_data, json=json_data, timeout=5)
        except Exception, e:
            i = i + 1
            time.sleep(1)
            log_warning("requests err {}, time:{}".format(repr(e), i))
            continue
        break
    if i >= 3:
        return None
    log_debug('response:{reponse}'.format(response=response))
    if response.status_code == 200:
        try:
            return response.json()
        except Exception, e:
            log_warning('get_url get exception {}'.format(repr(e)))
            return None
    else:
        return None

def daemonlize(pid_file):
    # 1. daemonlize
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, e:
        log_err("fork #1 failed: %d (%s)" %
                  (e.errno, e.strerror))
        sys.exit(1)
    # decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)
    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent, print eventual PID before
            log_info("Daemon PID %d" % pid)
            with open(pid_file, 'w+') as f:
                f.write('{pid}'.format(pid=pid))
            sys.exit(0)
    except OSError, e:
        log_err("fork #2 failed: %d (%s)" % (e.errno,
                                             e.strerror))
        sys.exit(1)
'''
def netmask_int_to_a(v):
    netmask = socket.inet_ntoa(struct.pack('!I', (1<<32)-(1<<(32-v))))
    return netmask
'''
class ExecEnv(object):
    def __init__(self, prefix, cxt='', desc='', raiseup=True):
        super(ExecEnv, self).__init__()
        self.desc = desc
        self.cxt = cxt
        self.prefix = prefix
        self.raiseup = raiseup
    def __enter__(self):
        log_debug('[%s] %s - start -' % (self.prefix, self.desc))
        return self
    def __exit__(self, exception_type, value, traceback):
        if self.cxt:
            log_debug('[%s] context:\n%s\n' % (self.prefix, self.cxt))
        #log_debug('[%s] %s - exit with %s:%s:%s -' % (self.prefix, self.desc, exception_type, value, type(traceback)))
        if exception_type:
            #log_crit('[%s] exception: <%s> : %s\n%s' % (self.prefix, exception_type, value, traceback.format_exc()))
            #log_crit('[%s] exception: <%s> : %s\n%s' % (self.prefix, exception_type, value, str(traceback)))
            log_err('[%s] exception :> %s >< %s <%s:%s>' % (self.prefix, exception_type, value, traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))
            log_err('[%s] %s - failed -' % (self.prefix, self.desc))
            return not self.raiseup
        log_debug('[%s] %s - done -' % (self.prefix, self.desc))
        return True

class OakmgrEnvelope(object):
    def __init__(self, mailbox, operate_type, cookie_id=0, pri=1, timeout=0):
        super(OakmgrEnvelope, self).__init__()
        self.mailbox = mailbox
        self.pri = pri
        self.timeout = timeout
        self.msg = {
            'operate_type': operate_type,
            'cookie_id': cookie_id,
        }

    def send(self, json_data):
        self.msg['timestamp'] = int(time.time())
        self.msg['data'] = json.dumps(json_data)
        self.mailbox.pub(const.STATUS_Q, (self.pri, self.msg), timeout=self.timeout)


class SystemCall(object):
    def __init__(self, debug=False):
        super(SystemCall, self).__init__()
        self.debug = debug
    
    def _call(self, cmd, comment='', path='', debug=True):
        '''
        cmd = ['/lib/okos/bin/set_..._.sh', '33', '201'] ; shell = False
        cmd = ['/lib/okos/bin/set_..._.sh 33 201'] ; shell = True
        '''
        
        if self.debug:
            if comment:
                log_debug(comment)
            log_debug("System Call - %s - " % (cmd))
        try:
            cmd = [str(c) for c in cmd]
            if not cmd[0].startswith('/') and path:
                cmd[0] = path + cmd[0]
            res = subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            log_warning("Execute System Call %s failed!" % (e.cmd))
            return False
        except Exception as e:
            log_warning("Execute System Call %s failed with %s!" % (cmd, type(e).__name__))
            return False
        if self.debug:
            log_debug("System Call - %s - return %d" % (cmd, res))
        return res == 0 and True or False

    def _output(self, cmd, comment='', path='', debug=True):
        '''
        cmd = ['/lib/okos/bin/set_..._.sh', '33', '201'] ; shell = False
        cmd = ['/lib/okos/bin/set_..._.sh 33 201'] ; shell = True
        '''
        
        if self.debug:
            if comment:
                log_debug(comment)
            log_debug("System Call - %s - " % (cmd))
        try:
            cmd = [str(c) for c in cmd]
            if not cmd[0].startswith('/') and path:
                cmd[0] = path + cmd[0]
            res = subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            log_warning("Execute System Call %s failed[%s] :> %s" % (e.cmd, e.returncode, e.output))
            return ''
        except Exception as e:
            log_warning("Execute System Call %s failed with %s!" % (cmd, type(e).__name__))
            return ''
        if self.debug:
            log_debug("System Call - %s - return %s" % (cmd, res))
        return res
    
    def localip2target(self, target):
        '''
        Get local information about route to target
        noly support ip address of target
        example:
            gateway, interface, localip = SystemCall().localip2taregt('13.112.4.123')

        '''
        p = const.FMT_PATTERN['ipaddr']
        if not p.match(target):
            target = socket.gethostbyname(target)
        p = re.compile('^[0-9.]{7,15}[ ]+via[ ]+([0-9.]{7,15})[ ]+dev[ ]+([a-z_0-9]+)[ ]+src[ ]+([0-9.]{7,15})')
        res = p.match(self._output(['ip', 'route', 'get', target]))
        return res and res.groups() or ('','','')