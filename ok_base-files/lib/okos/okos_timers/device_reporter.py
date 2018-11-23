
from okos_tools import *
from constant import const


class DeviceInfoEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(DeviceInfoEnv, self).__init__('Device Infor', desc=desc, raiseup=False, debug=debug)


class DeviceReporter(Poster):
    def __init__(self, mailbox, operate_type=const.DEV_INFO_OPT_TYPE, name='DeviceInfoTimer', interval=60, debug=False):
        super(DeviceReporter, self).__init__(name, interval=interval, mailbox=mailbox, operate_type=operate_type, repeated=True, debug=debug)
        self.productinfo_data = PRODUCT_INFO.renew()
        self.capwap_server = CAPWAP_SERVER.renew()
        self.conf = OKOS_CONFIG
        self.debug = debug
        
    def handler(self, *args, **kwargs):
        with DeviceInfoEnv('Collect Device Infor', debug=self.debug):
            data_json = {}
            productinfo_data = self.productinfo_data
            data_json['software_version'] = productinfo_data['swversion']
            data_json['boot_version'] = productinfo_data['bootversion'] or 'v1.1.1'
            data_json['cpu'] = productinfo_data['cpu']
            data_json['memory'] = productinfo_data['mem']
            data_json['eth_port'] = productinfo_data['eth_port']
            data_json['sn'] = productinfo_data['serial']
            data_json['product_name'] = productinfo_data['model']
            data_json['config_version'] = self.conf.version

        with DeviceInfoEnv('Collect info for config_version_webui', debug=self.debug):
            #data_json['config_version_webui'] = ubus.call('uci', 'get', {"config":"system", "section":"@system[0]", "option":"config_version_webui"})[0]["value"]
            data_json['config_version_webui'] = UciSection('system', 'system')['config_version_webui']
        with DeviceInfoEnv('Collect info for local ip address', debug=self.debug):
            #mas_server = ubus.call('uci', 'get', {'config':'capwapc', 'section':'server'})[0]['values'].setdefault('mas_server', '')
            mas_server = self.capwap_server['mas_server']
            _, _, data_json['internal_ip'] = SystemCall(debug=False).localip2target(mas_server)
            
        return data_json
