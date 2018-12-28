from conf_handlers import ConfHandler
from constant import const
from okos_tools import *
import ubus
import json
import time
import subprocess
from datetime import datetime
import os
import socket
import struct
from signal import SIGKILL

class Diag(ConfHandler):
    def __init__(self, mailbox, debug=False):
        super(Diag, self).__init__(mailbox, const.DEV_DIAG_REQ_OPT_TYPE, const.DEV_DIAG_RESP_OPT_TYPE, name='Diag', debug=debug)
    def _handler(self, request):
        '''
        name: e0
        ip_type: 0 - dhcp, 2 - pppoe
        pppoe_username:
        pppoe_password:
        dnss
        '''
        data = json.loads(request['data'], encoding='utf-8')
        log_err("+++++++++>{}".format(data))
        ret = {}
        name = data['name']
        ret['name'] = name
        if name == 'e0':
            lname = "wan"
        elif name == 'e1':
            lname = "wan1"
        elif name == 'e2':
            lname = "wan2"
        else:
            log_warning('{} is not a wan'.format(name))
            ret['error_code'] = 1
            return ret

        if data['ip_type'] == 0: # dhcp
            try:
                param = {'config':'network', 'section':lname, 'values':{'proto':'dhcp', 'defaultroute':0}}
                ubus.call('uci', 'set', param)
                ubus.call('uci', 'commit', {'config':'network'})
                # reload network
                ubus.call('network', 'reload', {})
                time.sleep(5)
            except Exception, e:
                log_warning("name:{} diag failure, {}".format(name, e))
                ret['error_code'] = const.COMMON_FAILURE
                return ret

        elif data['ip_type'] == 2: # pppoe
            try:
                param = {'config':'network', 'section':lname, 'values':{'proto':'pppoe', 'username':'magictry', 'password':data['pppoe_password'], 'defaultroute':0}}
                ubus.call('uci', 'set', param)
                ubus.call('uci', 'commit', {'config':'network'})
                ubus.call('network', 'reload', {})
                time.sleep(1)
                param = {'config':'network', 'section':lname, 'values':{'proto':'pppoe', 'username':data['pppoe_username'], 'password':data['pppoe_password'], 'defaultroute':0}}
                ubus.call('uci', 'set', param)
                ubus.call('uci', 'commit', {'config':'network'})
                # monitor log
                ps = subprocess.Popen('logread -f', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True,cwd='/tmp',preexec_fn=os.setsid)
                ubus.call('network', 'reload', {})
                ret['error_code'] = const.PPPOE_CAN_NOT_CONNECTED
                old = datetime.now()
                while True:
                    if (datetime.now() - old).seconds >= 60:
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        ret['error_code'] = const.PPPOE_CAN_NOT_CONNECTED # timeout
                        break
                    data = ps.stdout.readline()
                    # print "xxx>:{}:<xxx".format(data)
                    if data == b'':
                        if ps.poll() is not None:
                            break
                    elif data.find('Unable to complete PPPoE Discovery') != -1:
                        ret['error_code'] = const.PPPOE_DISCOVERY_ERROR # discovery error
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        break
                    elif data.find('Serial link appears to be disconnected') != -1:
                        ret['error_code'] = const.PPPOE_AUTH_ERR # LCP error
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        break
                    elif data.find('CHAP authentication failed: Access denied') != -1:
                        ret['error_code'] = const.PPPOE_AUTH_ERR # authentication error
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        break
                    elif data.find('Received bad configure-ack') != -1:
                        ret['error_code'] = const.COMMON_SUCCESS # authentication error
                        os.killpg(os.getpgid(ps.pid), SIGKILL)
                        break
                return ret

            except Exception, e:
                log_warning("name:{} diag failure, {}".format(name, e))
                ret['error_code'] = const.PPPOE_CAN_NOT_CONNECTED
                return ret

        else: # other not support
            log_warning("ip_type:{} is not supported for diag".format(data['ip_type']))
            ret['error_code'] = const.COMMON_FAILURE
            return ret

        try:
            # get if status
            if_status = ubus.call('network.interface.{}'.format(lname), 'status', {})[0]
            # init ret
            ret['error_code'] = const.COMMON_SUCCESS
            ret['ip'] = if_status['ipv4-address'][0]['address']
            ns_int = if_status['ipv4-address'][0]['mask']
            ret['netmask'] =  socket.inet_ntoa(struct.pack('!I', (1<<32)-(1<<(32-ns_int))))
            ret['gateway'] = if_status['route'][0]['target']
            ret['dnss'] = ""
            for dns in if_status['dns-server']:
                if not ret['dnss']:
                    ret['dnss'] = dns
                else:
                    ret['dnss'] = ret['dnss'] + ',' + dns
            # revert config
            #ubus.call('uci', 'revert', {'config':'network'})
            #ubus.call('network', 'reload', {})
        except Exception, e:
            log_warning("name:{} diag failure, {}".format(name, e))
            ret['error_code'] = const.CAN_NOT_GET_IP
            return ret
