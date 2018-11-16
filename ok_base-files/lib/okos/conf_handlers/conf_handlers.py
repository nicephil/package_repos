from constant import const
from okos_tools import log_debug, log_warning, okos_system_log_info, okos_system_log_err, log_err
from okos_tools import set_whole_confinfo, get_whole_conf_bak_path, get_whole_conf_path, rollback_whole_confinfo
import time
import os
from okos_tools import Envelope
from okos_tools import UciSection
import json
from datetime import datetime
from signal import SIGKILL
import subprocess
import socket
import struct
import ubus

class ConfHandler(object):
    def __init__(self, mailbox, request_id, response_id, pri=1, debug=False, name='ConfHandler'):
        super(ConfHandler, self).__init__()
        self.name = name
        self.request_id = request_id
        self.response_id = response_id
        self.env = Envelope(mailbox, operate_type=response_id, pri=pri)
        self.debug = debug
    def handler(self, request):
        self.debug and log_debug('[%s] request - start -' % (self.name))
        res = self._handler(request)
        if res:
            self.env.go(res, request['cookie_id'])
            self.debug and log_debug('[%s] reply - sent out - with <%s>' % (self.name, res))
        self.debug and log_debug('[%s] request - done -' % (self.name))
    def _handler(self, request):
        pass


class ConfRequest(ConfHandler):
    def __init__(self, mailbox):
        super(ConfRequest, self).__init__(mailbox, const.DEV_CONF_OPT_TYPE, const.DEV_CONF_RESP_OPT_TYPE, name='ConfRequest')
    def _handler(self, request):
        self.confinfo_data = set_whole_confinfo(request['data'])
        okos_system_log_info("configuration data obtained")
        time.sleep(3)
        ret = os.system("{} -o {} {}".format(const.OKOS_CFGDIFF_SCRIPT, get_whole_conf_bak_path(), get_whole_conf_path()))
        if ret != 0:
            okos_system_log_err("configuration loaded failed")
            self.confinfo_data = rollback_whole_confinfo()
        else:
            okos_system_log_info("configuration loaded successfully")
        json_data = {}
        json_data['config_version'] = self.confinfo_data['config_version']
        json_data['error_code'] = ret
        return json_data

class WebUiConf(ConfHandler):
    def __init__(self, mailbox):
        super(WebUiConf, self).__init__(mailbox, const.DEV_WEBUI_CONF_REQ_OPT_TYPE, const.DEV_WEBUI_CONF_RESP_OPT_TYPE, name='WebUiConf')
    def _handler(self, request):
        json_data = {}
        try:
            json_data['hostname'] = UciSection('system', 'system')['device_name']
        except Exception, e:
            log_err("ubus err {}".format(e))
        json_data['e0'] = self.webuiconf_parse('wan')
        json_data['e3'] = self.webuiconf_parse('lan4053')
        return json_data

    def webuiconf_parse(self, sid):
        network_conf={}
        dhcp_conf={}
        webui_conf={}
        try:
            network_conf = ubus.call('uci', 'get', {"config":"network"})[0]["values"]
            dhcp_conf = ubus.call('uci', 'get', {"config":"dhcp"})[0]["values"]
            webui_conf = ubus.call('uci', 'get', {"config":"webui_config"})[0]["values"]
        except Exception, e:
            log_err("can not get config by ubus {}".format(e))

        e_data = {}
        e_data['type'] = 0
        e_proto = network_conf[sid]['proto']
        if e_proto == "dhcp":
            e_data['ip_type'] = 0
        elif e_proto == "static":
            e_data['ip_type'] = 1
            e_data['ips'] = []
            e_data['ips'].append({})
            e_data['ips'][0]['ip'] = network_conf[sid]['ipaddr']
            e_data['ips'][0]['netmask'] = network_conf[sid]['netmask']
            if 'gateway' in network_conf[sid]:
                e_data['gateway'] = network_conf[sid]['gateway']
            if 'dns' in network_conf[sid]:
                e_data['dnss'] = ""
                for _dns in network_conf[sid]['dns']:
                    if not e_data['dnss']:
                        e_data['dnss'] = _dns
                    else:
                        e_data['dnss'] = e_data['dnss'] + "," + _dns
            if sid == 'lan4053':
                e_data['type'] = 1
                e_data['ips'][0]['ip'] = webui_conf[sid]['ipaddr']
                e_data['ips'][0]['netmask'] = webui_conf[sid]['netmask']
                e_data['dhcp_start'] = int(webui_conf[sid]['dhcp_start'])
                e_data['dhcp_server_enable'] = int(webui_conf[sid]['dhcp_server_enable'])
                e_data['dhcp_limit'] = int(webui_conf[sid]['dhcp_limit'])
                e_data['dhcp_leasetime'] = int(webui_conf[sid]['dhcp_leasetime'])
        elif e_proto == "pppoe":
            e_data['ip_type'] = 2
            e_data['pppoe_username'] = network_conf[sid]['username']
            e_data['pppoe_password'] = network_conf[sid]['password']
        return e_data

class Diag(ConfHandler):
    def __init__(self, mailbox):
        super(Diag, self).__init__(mailbox, const.DEV_DIAG_REQ_OPT_TYPE, const.DEV_DIAG_RESP_OPT_TYPE, name='Diag')
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

class Reboot(ConfHandler):
    def __init__(self, mailbox):
        super(Reboot, self).__init__(mailbox, const.DEV_REBOOT_OPT_TYPE, 0, name='Reboot')
    def _handler(self, request):
        okos_system_log_info("device is reset from nms request")
        time.sleep(5)
        os.system('reboot')

class Upgrade(ConfHandler):
    def __init__(self, mailbox):
        super(Upgrade, self).__init__(mailbox, const.DEV_UPGRADE_REQ_OPT_TYPE, const.DEV_UPGRADE_RESP_OPT_TYPE, name='Upgrade')
    def _handler(self, request):
        ret = 0
        data = json.loads(request['data'], encoding='utf-8')
        log_err("+++++++++>{}".format(data))
        url = data['url']
        timeout = data['timeout']
        okos_system_log_info("get upgrade firmware request")
        ret = os.system("wget -q -T {} -O - \'{}\' | tail -c +65 | tar xzf - -O > {}".format(timeout, url, const.CST_IMG_TMP_FILE))
        if ret != 0:
            okos_system_log_err("download firmware failed, errcode:{}".format(ret))
            os.system("(sleep 20;reboot)&")
            ret = 1
            return ret

        okos_system_log_info("downloaded firmware size:{}, writing firmware to disk".format(os.path.getsize(const.CST_IMG_TMP_FILE)))
        ret = os.system("(sleep 1;sysupgrade {} )&".format(const.CST_IMG_TMP_FILE))
        if ret != 0:
            okos_system_log_info("upgrade firmware failed, errcode:{}".format(ret))
        json_data = {}
        json_data['error_code'] = ret
        return json_data
