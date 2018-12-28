import functools
import threading
from okos_tools import log_debug, log_err, ExecEnv, Envelope


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
        self.debug and log_debug('[Timer] %s is created' % (self.name))

    def handler(self, *args, **kwargs):
        log_err("You should implement A handler")
        raise NotImplementedError

    def start(self):
        self.debug and log_debug("[Timer] %s is kicked off" % self.name)
        self._timer.start()
    def repeat(self):
        def wrapper(*args, **kwargs):
            self.debug and log_debug('[Timer] %s start to execute:' % (self.name))
            res = False
            if self.repeated:
                with ExecEnv('Timer', desc='periodic process', raiseup=False, debug=self.debug) as _X:
                    res = self.handler(*args, **kwargs)
                self._timer = threading.Timer(self.interval, self.repeat())
                self._timer.name = self.name
                self.start()
            else:
                with ExecEnv('Timer', desc='One time shot process', raiseup=False, debug=self.debug) as _X:
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
    def __init__(self, name, interval, mailbox=None, operate_type=0, repeated=False, pri=200, debug=False):
        super(Poster, self).__init__(name=name, interval=interval, repeated=repeated, debug=debug)
        self.env = Envelope(mailbox, operate_type=operate_type, pri=pri, debug=debug)
        self.debug = debug
    def repeat(self):
        def wrapper(*args, **kwargs):
            self.debug and log_debug('[Poster] %s start to execute:' % (self.name))
            message = None
            if self.repeated:
                with ExecEnv('Poster', desc='periodic process', raiseup=False, debug=self.debug) as _X:
                    message = self.handler(*args, **kwargs)
                self._timer = threading.Timer(self.interval, self.repeat())
                self._timer.setName(self.name)
                self.start()
            else:
                with ExecEnv('Poster', desc='One time shot process', raiseup=False, debug=self.debug) as _X:
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
            self.debug and log_debug('[InTimePoster] %s start to execute:' % (self.name))
            message, ts = None, None
            if self.repeated:
                with ExecEnv('InTimePoster', desc='periodic process', raiseup=False, debug=self.debug) as _X:
                    message, ts = self.handler(*args, **kwargs)
                self._timer = threading.Timer(self.interval, self.repeat())
                self._timer.setName(self.name)
                self.start()
            else:
                with ExecEnv('InTimePoster', desc='One time shot process', raiseup=False, debug=self.debug) as _X:
                    message, ts = self.handler(*args, **kwargs)
            message and self.env.go(message, timestamp=ts)
            return message
        return wrapper


class HierarchicPoster(Poster):
    '''
    This timer is used to implement a hirachical timer.
    '''
    def __init__(self, name, interval, mailbox, operate_type, pri, debug=False):
        super(HierarchicPoster, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug, pri=pri)
        self.debug = debug
        self._actions = []
    def add_layer(self, name, interval, func):
        self._actions.append({'name':name, 'interval':interval, 'func':func, 'counter': 0})
    def _action(self, cargo, fx):
        fx['counter'] = fx['counter']+1 if fx['counter'] < fx['interval'] else 1
        self.debug and log_debug('[HierarchicPoster] Layer<{name}> round {counter}/{interval}'.format(name=fx['name'], counter=fx['counter'], interval=fx['interval']))
        if fx['counter'] >= fx['interval']:
            fx['func'](cargo)
            return True
        else:
            return False

    @staticmethod
    def hierarchic(handler):
        def wrapper(self, *args, **kwargs):
            cargo = {}
            for action in self._actions:
                if not self._action(cargo, action):
                    break
            return handler(self, cargo, *args, **kwargs)
        return wrapper


            
