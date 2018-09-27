import fcntl
from subprocess import Popen, PIPE
import logging
import logging.handlers
logging.basicConfig(
    level=logging.DEBUG,
    filemode='w',
    format='[%(threadName)s-%(thread)d]: %(message)s',
)
MyLogger = logging.getLogger('MyLogger')
_h = logging.handlers.SysLogHandler('/dev/log')
MyLogger.addHandler(_h)
MyLogger.propagate = False

import requests
import json
import os
import sys
import time
import syslog
import ubus

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
    MyLogger.debug(msg)

def log_info(msg):
    MyLogger.info(msg)

def log_warning(msg):
    MyLogger.warning(msg)

def log_err(msg):
    MyLogger.error(msg)

def log_crit(msg):
    MyLogger.critical(msg)

def logit(func):
    def wrapper(*args, **kwargs):
        log_debug("Start to <%s:%s>:" % (args[0].__class__.__name__, func.__name__))
        res = func(*args, **kwargs)
        log_debug("<%s:%s> is done." % (args[0].__class__.__name__, func.__name__))
        #log_debug("<%s> is done." % func.__name__)
        return res
    return wrapper

config_conf_file = ''.join([const.CONFIG_DIR, const.CONFIG_CONF_FILE])

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
    productinfo_data={}
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
    log_debug('url:{url}'.format(url=url))
    log_debug('param_data:{param_data}'.format(param_data=param_data))
    log_debug('json_data:{json_data}'.format(json_data=json_data))
    i = 0
    while i < 3:
        try:
            response = requests.post(url, params=param_data, json=json_data, files=files, timeout=5)
        except Exception, e:
            i = i + 1
            time.sleep(1)
            log_warning("requests err {}, time:{}".format(repr(e), i))
            continue
        break

    if i >=3:
        return None

    if response.status_code == 200:
        try:
            log_debug('response:status:{status},json:{json}'.format(status=response.status_code, json=response.json()))
            return response.json()
        except Exception, e:
            log_warning('post_url get exception {}'.format(repr(e)))
            return None
    else:
        log_warning('response:status:{status},response:{response}'.format(status=response.status_code, response=response))
        return None

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


