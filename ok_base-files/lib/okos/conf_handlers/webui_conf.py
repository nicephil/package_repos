from conf_handlers import ConfHandler
from constant import const
from okos_tools import *
import ubus

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
