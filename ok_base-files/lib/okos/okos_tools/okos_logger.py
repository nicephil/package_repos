import syslog
import threading


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

def okos_sta_log_info(msg):
	syslog.openlog("200-STA", syslog.LOG_NDELAY, syslog.LOG_USER)
	syslog.syslog(syslog.LOG_INFO, msg)
	syslog.closelog()

def okos_sta_log_warn(msg):
	syslog.openlog("200-STA", syslog.LOG_NDELAY, syslog.LOG_USER)
	syslog.syslog(syslog.LOG_WARNING, msg)
	syslog.closelog()

def okos_sta_log_err(msg):
	syslog.openlog("200-STA", syslog.LOG_NDELAY, syslog.LOG_USER)
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
        this = args[0]
        cname = this.__name__ if isinstance(this, type) else this.__class__.__name__
        fname = func.__name__
        log_debug("[Config] Start to <{T}:{func}>:".format(T=cname, func=fname))
        res = func(*args, **kwargs)
        log_debug("[Config] <{T}:{func}> is done.".format(T=cname, func=fname))
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
