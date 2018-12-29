from okos_tools import CAPWAP_SERVER, log_warning, log_debug, okos_system_log_info, UciSection, post_url, okos_system_log_warn
import os
import json
from constant import const
import socket

class Oakmgr(object):
    def __init__(self, mailbox, debug=False):
        super(Oakmgr, self).__init__()
        self.mailbox = mailbox
        self.device_mac = UciSection('productinfo', 'productinfo')['mac']
        self.pipe_name = '/tmp/okos_mgr.pipe'
        self.pipe_f = self.create_pipe(self.pipe_name)
        self.capwap = CAPWAP_SERVER.renew()
        self.first_access_nms = True
        self.debug = debug

    def create_pipe(self, pipe_name):
        pipe_f = None
        try:
            os.remove(self.pipe_name)
        except Exception, e:
            pass
        try:
            os.mkfifo(pipe_name)
            pipe_f = os.open(self.pipe_name, os.O_SYNC |os.O_CREAT | os.O_RDWR|os.O_NONBLOCK)
        except Exception, e:
            log_warning("mkfifo error: {}".format(e))
            pipe_f = None
        return pipe_f

    def access_pipe(self):
        try:
            s = os.read(self.pipe_f, 4096)
            self.debug and log_debug('PIPE : %s' % (s))
            s = s.strip('\n')
            json_d = json.loads(s, encoding='utf-8')
            self.debug and log_debug('JSON : %s' % (json_d))
        except Exception as e:
            json_d = {}
        return json_d

    def access(self, msgs):
        server = (self.capwap['mas_server'], 80, 'nms')
        url = 'http://{server}:{port}/{path}/api/device/router/info'.format(server=server[0], port=server[1], path=server[2])
        post_data = {
            'mac' : self.device_mac,
            'delay' : const.HEARTBEAT_DELAY,
            'list' : msgs,
        }

        self.debug and map(lambda m: log_debug('<operate_type:{op}>>cookie:{c}>>{data}'.format(op=m['operate_type'], c=m['cookie_id'], data=m['data'])), msgs)
        requested = post_url(url, json_data=post_data, debug=self.debug)
        if self.first_access_nms:
            self.first_access_nms = False
            try:
                okos_system_log_info("connected to oakmgr @{}".format(socket.gethostbyname(server[0])))
            except Exception as e:
                okos_system_log_info("connected to oakmgr @{}".format(server[0]))
        if requested and 'error_code' in requested and requested['error_code'] == 1002:
            okos_system_log_warn("oakmgr-{} reject access".format(server))
        else:
            self.debug and log_debug('=>OakSDC({svr}): [{mac}] send data successfully!'.format(mac=post_data['mac'], svr=server))

        requested = self.access_pipe() or requested

        for r in requested.setdefault('list', []):
            self.debug and log_debug('<=OakSDC: REQUESTED data: %s' % (r))
            self.mailbox.pub(const.CONF_REQUEST_Q, r, timeout=0)
