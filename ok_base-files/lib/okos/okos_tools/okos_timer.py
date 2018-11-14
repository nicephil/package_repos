import functools
import threading
from okos_logger import log_debug
from envelope import Envelope


class Timer(object):
    '''
    This is basic class of timer. You can control:
    1) whether it is repeatable;
    2) whether you want to kickoff it right now;
    3) Interval of the timer
    Usage:
    Timer('GoodBoy', interval=100, repeated=True, Now=False, debug=True)
    '''
    def __init__(self, name='', interval=60, repeated=False, now=True, debug=False):
        super(Timer, self).__init__()
        self.name = name
        self.interval = interval
        self.repeated = repeated
        self._timer = threading.Timer(now and 1 or self.interval, self.repeat())
        self._timer.name = self.name
        self.debug = debug
        self.debug and log_debug('Timer %s is created' % (self.name))

    def handler(self, *args, **kwargs):
        log_debug("I am in the handler")
        pass
    def start(self):
        self.debug and log_debug("Timer %s is kicked off" % self.name)
        self._timer.start()
    def repeat(self):
        def wrapper(*args, **kwargs):
            self.debug and log_debug('Timer %s start to execute:' % (self.name))
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
    '''
    This timer is used to report message to SDC. So, beside the basic timer,
    It is added an Envelop object to help package and send message to SDC.
    So, you have to add parameters:
    1) mailbox object you want to use;
    2) operate_type: Such as the destination address of a mail.
    3) priority of the message, you can identify priority when sending either.
    '''
    def __init__(self, name, interval, mailbox, operate_type, repeated=False, pri=200, debug=False):
        super(Poster, self).__init__(name=name, interval=interval, repeated=repeated, debug=debug)
        self.env = Envelope(mailbox, operate_type=operate_type, pri=pri)
    def repeat(self):
        def wrapper(*args, **kwargs):
            self.debug and log_debug('Timer %s start to execute:' % (self.name))
            if self.repeated:
                message = self.handler(*args, **kwargs)
                self._timer = threading.Timer(self.interval, self.repeat())
                self._timer.setName(self.name)
                self.start()
            else:
                message = self.handler(*args, **kwargs)
            message and self.env.go(message)
            return message
        return wrapper

class InTimePoster(Timer):
    '''
    This is a special Poster to let you identify the timestamp of the sending message.
    '''
    def __init__(self, name, interval, mailbox, operate_type, repeated=False, pri=200, debug=False):
        super(InTimePoster, self).__init__(name=name, interval=interval, repeated=repeated, debug=debug)
        self.env = Envelope(mailbox, operate_type=operate_type, pri=pri)
    def repeat(self):
        def wrapper(*args, **kwargs):
            self.debug and log_debug('Timer %s start to execute:' % (self.name))
            if self.repeated:
                message, ts = self.handler(*args, **kwargs)
                self._timer = threading.Timer(self.interval, self.repeat())
                self._timer.setName(self.name)
                self.start()
            else:
                message, ts = self.handler(*args, **kwargs)
            message and self.env.go(message, timestamp=ts)
            return message
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

