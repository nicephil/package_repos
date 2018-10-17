#!/usr/bin/python
import time
import okos_utils
import threading
import  okos_mailbox
import status_mgr
import conf_mgr
import json
import os
import socket
import sys
import ubus

from okos_utils import log_crit, log_err, log_warning, log_info, log_debug, okos_system_log_info
from constant import const

class OKOSMgr(object):
    def __init__(self):
        self.productinfo_data = okos_utils.get_productinfo()
        okos_system_log_info("oakos is up, version:{}".format(self.productinfo_data['swversion']))
        self.process_heartbeat_thread = None
        self.collect_status_thread = None
        self.process_request_term = False
        self.collect_status_term = False
        self.pipe_name = '/tmp/okos_mgr.pipe'
        self.pipe_f = self.create_pipe(self.pipe_name)
        self.init_modules()
        self.first_access_nms= True

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

    def access_fifo(self):
        try:
            s = os.read(self.pipe_f, 4096)
            s = s.strip('\n')

            json_d = {}
            json_d = json.loads(s, encoding='utf-8')
        except Exception, e:
            json_d = None
        log_debug("===>fifo:{}".format(json_d))
        return json_d

    def init_system(self):
        os.system(const.INIT_SYS_SCRIPT);

    def init_modules(self):
        self.init_system();
        self.mailbox = okos_mailbox.MailBox()
        self.conf_mgr = conf_mgr.ConfMgr(self.mailbox)
        self.status_mgr = status_mgr.StatusMgr(self.mailbox, self.conf_mgr)
        self.start_collect_status()
        self.conf_mgr.start()
        self.status_mgr.start()
        self.start_process_heartbeat()

    def start_process_heartbeat(self):
        self.process_heartbeat_thread = threading.Thread(target=self.process_heartbeat, name='process_heartbeat')
        self.process_heartbeat_thread.start()

    def start_collect_status(self):
        self.collect_status_thread = threading.Thread(target=self.collect_status, name='collect_status')
        self.collect_status_thread.start()

    def collect_status(self):
        while not self.collect_status_term:
            msg = self.mailbox.sub(const.STATUS_Q)
            # emergency status
            if msg[0] < 10:
                msg_list = []
                msg_list.append(msg[1])
                temp = self.mailbox.get_all(const.STATUS_Q)
                if temp:
                    for i in temp:
                        msg_list.append(i[1])
                post_data = self.contract_post_data(msg_list)
                request_data = self.access_nms(post_data)
                self.dispatch_request(request_data)
            else:
                self.mailbox.pub(const.HEARTBEAT_Q, msg[1], timeout=0)

    def contract_post_data(self, msg):
        post_data = {
            'mac' : self.productinfo_data['mac'],
            'delay' : const.HEARTBEAT_DELAY
        }
        post_data['list'] = []
        if msg:
            l = []
            d = {}
            for i in msg:
                k = i['operate_type']
                d[k] = i
            post_data['list'] = [v for k,v in d.items()]
        return post_data

    def dispatch_request(self, request_data):
        if request_data:
            try:
                list_data = request_data['list']
            except Exception, e:
                log_warning("no list key in list_data:%s" % (str(e)))
                list_data = {}
            log_debug("xxxxxxxxxx>{}<xxxxxxxxx".format(list_data))
            for i,v in enumerate(list_data):
                self.mailbox.pub(const.CONF_REQUEST_Q, v, timeout=0)

    def process_heartbeat(self):
        while not self.process_request_term:
            # 1. prepare post data
            msg  = self.mailbox.get_all(const.HEARTBEAT_Q)
            post_data = self.contract_post_data(msg)

            # 2. access_nms
            request_data = self.access_nms(post_data)

            # 3. pass data and send msg to mailbox
            self.dispatch_request(request_data)

            # 4. have a sleep
            time.sleep(const.HEARTBEAT_TIME)

    def access_nms(self, post_data):
        capwapc_data = self.conf_mgr.get_capwapc()
        server = (capwapc_data['mas_server'], 80, 'nms')
        #server = ('192.168.254.141', 8080, 'nms-webapp')
        url = 'http://{server}:{port}/{path}/api/device/router/info'.format(server=server[0], port=server[1], path=server[2])
        request_data = okos_utils.post_url(url, json_data=post_data)
        if self.first_access_nms:
            self.first_access_nms = False
            okos_system_log_info("connected to oakmgr @{}".format(socket.gethostbyname(server[0])))
        if request_data and 'error_code' in request_data and request_data['error_code'] == 1002:
            okos_system_log_info("device is reset as nms reject access")
            time.sleep(5)
            os.system("reboot -f")
        tmp = self.access_fifo()
        if tmp:
            request_data = tmp
        return request_data

    def join_threads(self):
        self.process_heartbeat_thread.join()
        self.collect_status_thread.join()

def main():
    ubus.connect()
    if len(sys.argv) <= 1:
        pid_file = '/var/run/okos_mgr.pid'
        okos_utils.daemonlize(pid_file)
    okos_mgr = OKOSMgr()
    okos_mgr.join_threads()
    ubus.disconnect()

if __name__ == '__main__':
    main()
