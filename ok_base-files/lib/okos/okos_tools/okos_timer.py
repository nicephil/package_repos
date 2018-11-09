import functools
import threading
from okos_logger import log_debug
from envelope import Envelope


class Timer(object):
    def __init__(self, name='', interval=10, repeated=False, now=True, debug=True):
        super(Timer, self).__init__()
        self.name = name
        self.interval = interval
        self.repeated = repeated
        self._timer = threading.Timer(now and 1 or self.interval, self.repeat())
        self._timer.name = self.name
        self.debug = debug
        if self.debug:
            log_debug('Timer %s is created' % (self.name))

    def handler(self, *args, **kwargs):
        log_debug("I am in the handler")
        pass
    def start(self):
        if self.debug:
            log_debug("Timer %s is kicked off" % self.name)
        self._timer.start()
    def repeat(self):
        def wrapper(*args, **kwargs):
            if self.debug:
                log_debug('Timer %s start to execute:' % (self.name))
            if self.repeated:
                res = self.handler(*args, **kwargs)
                self._timer = threading.Timer(self.interval, self.repeat())
                self._timer.name = self.name
                self.start()
            else:
                res = self.handler(*args, **kwargs)
            return res
        return wrapper


class Poster(Timer):
    def __init__(self, name, interval, mailbox, operate_type, repeated=False, pri=200):
        super(Poster, self).__init__(name, interval, repeated)
        self.env = Envelope(mailbox, operate_type=operate_type, pri=pri)
    def repeat(self):
        def wrapper(*args, **kwargs):
            log_debug('Timer %s start to execute:' % (self.name))
            if self.repeated:
                res = self.handler(*args, **kwargs)
                self._timer = threading.Timer(self.interval, self.repeat())
                self._timer.setName(self.name)
                self.start()
            else:
                res = self.handler(*args, **kwargs)
            if res:
                self.env.go(res)
            return res
        return wrapper


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
        self._func = func
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
    def func(self):
        pass
            
class ReportTimer(object):
    def __init__(self, name, interval, func, mailbox, operate_type, pri=200):
        super(ReportTimer, self).__init__()
        self.name = name
        self.interval = interval
        self.func = func
        self.timer = threading.Timer(interval, self.repeat(func, interval))
        self.timer.setName(name)
        self.env = Envelope(mailbox, operate_type=operate_type, pri=pri)
        log_debug('Timer is created')
    def start(self):
        self.timer.start()
        log_debug('Timer is kicked off')
    def repeat(self, func, interval):
        def wrapper(*args, **kwargs):
            log_debug('Timer start to execute:')
            res = func(*args, **kwargs)
            if res:
                self.env.go(res)
            self.timer = threading.Timer(interval, self.repeat(func, interval))
            self.timer.setName(self.name)
            self.start()
            return res
        return wrapper

