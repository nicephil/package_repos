from conf_handlers import ConfHandler
from constant import const
from okos_tools import *
from cfgobjects import ParameterChecker, ConfigInputEnv
import json
import time

class DdnsTest(ConfHandler):
    '''
    This handler is used to test DDNS setting. So,
    firstly, It should apply a ddns setting;
    then, try to test whether or not it does work;
    after that, remove this temporary setting;
    finally, report the result.


    '''
    def __init__(self, mailbox, debug=False):
        super(DdnsTest, self).__init__(mailbox, const.DDNS_TEST_QUERY_OPT_TYPE, const.COMMON_RESULT_RESP_OPT_TYPE, debug=debug, name='Test DDNS Setting')
        self.debug = debug
        self.syscall = SystemCall(debug=self.debug)

    def _handler(self, request):
        new = json.loads(request['data'], encoding='utf-8')
        checker = ParameterChecker(new)
        test_id = 'okos_ddns_test'
        with ConfigInputEnv(new, 'DDNS test', debug=self.debug):
            #checker['id'] = (None, None)
            checker['interface_name'] = (None, None)
            checker['ip'] = (None, None)
            checker['provider'] = (None, None)
            checker['hostname'] = (None, None)
            checker['username'] = (None, None)
            checker['password'] = (None, None)
        cmd = ['set_ddns.sh', 'set', test_id, ]
        cmd += ['--provider', checker['provider'], '--domainname', checker['hostname'],
                '--username', checker['username'], '--password', checker['password'],
                '--interface', checker['interface_name'], '--ipaddr', checker['ip'],
                ]
        self.syscall._call(cmd, comment='DDNS entry test - add -', path=const.CONFIG_BIN_DIR)
        cmd = ['set_ddns.sh', 'stat', test_id, '--domainname', checker['hostname'], '--ipaddr', checker['ip'],]
        #time.sleep(3)
        res = self.syscall._output(cmd, comment='DDNS entry test - stat check -', path=const.CONFIG_BIN_DIR)
        cmd = ['set_ddns.sh', 'del', test_id, ]
        self.syscall._call(cmd, comment='DDNS entry test - del -', path=const.CONFIG_BIN_DIR)
        return {'error_code': 'success' in res and '0' or '1'}