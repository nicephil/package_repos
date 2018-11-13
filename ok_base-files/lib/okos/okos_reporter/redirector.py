
from okos_tools import *
from constant import const
import netifaces as ni
import md5


class Redirector(Timer):
    def __init__(self, name='Redirector', interval=120, debug=False):
        super(Redirector, self).__init__(name=name, interval=interval, repeated=True, debug=debug)
        self.product_info = PRODUCT_INFO.renew()
        self.capwap_server = CAPWAP_SERVER.renew()
        self.debug = debug

    def handler(self, *args, **kwargs):
        post_data = {}
        post_data['version'] = self.product_info['swversion']
        post_data['device'] = self.product_info['mac']
        post_data['device_type'] = self.product_info['production']
        post_data['manufacturer'] = self.product_info['model']
        post_data['sn'] = self.product_info['serial']
        try:
            post_data['private_ip'] = ni.ifaddresses(self.product_info['eth_port'])[ni.AF_INET][0]['addr']
            post_data['private_mask'] = ni.ifaddresses(self.product_info['eth_port'])[ni.AF_INET][0]['netmask']
        except Exception, e:
            try:
                post_data['private_ip'] = ni.ifaddresses('pppoe-wan')[ni.AF_INET][0]['addr']
                post_data['private_mask'] = ni.ifaddresses('pppoe-wan')[ni.AF_INET][0]['netmask']
            except Exception, e:
                log_info("can not get private_ip to query redirector, err:{}".format(e))                

        key = md5.new("{SALT}{_mac}".format(SALT=const.SALT, _mac=post_data['device'])).hexdigest()
        url="http://{_server_ip}:{PORT}/redirector/v1/device/register/?key={KEY}".format(_server_ip=const.DEFAULT_ADDR,
                                                                                            PORT=const.DEFAULT_PORT,
                                                                                            KEY=key)
        request_data = post_url(url, json_data=post_data, debug=True)
        '''
        print request_data
        import random
        if random.randint(1,100) % 2:
            request_data['oakmgr_pub_name'] = 'xxia.hz.oakridge.io'
        '''
        # 2. update the new capwapc fetched from redirector
        if request_data and 'oakmgr_pub_name' in request_data:
            if request_data['oakmgr_pub_name'] != self.capwap_server['mas_server']:
                self.debug and log_debug('Update CAPWAPC server setting from %s to %s' %(self.capwap_server['mas_server'], request_data['oakmgr_pub_name']))
                self.capwap_server['mas_server'] = request_data['oakmgr_pub_name']
                self.capwap_server.commit()
