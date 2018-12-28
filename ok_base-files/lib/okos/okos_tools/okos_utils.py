import fcntl
from subprocess import Popen, PIPE
from okos_logger import log_warning, log_debug, log_err, log_info
import requests
import json
import os
import sys
import time
import ubus
from constant import const
import re


config_conf_file = ''.join([const.CONFIG_DIR, const.CONFIG_CONF_FILE])

def set_capwapc(mas_server):
    """" set capwapc """
    try:
        ubus.call("uci", "set", {"config":"capwapc","section":"server", "values":{"mas_server":mas_server}})
        #_, _, localip = SystemCall().localip2target(mas_server)
        #ubus.call("uci", "set", {"config":"capwapc","section":"server", "values":{"local_ip":localip}})
        ubus.call("uci", "commit", {"config":"capwapc"})
    except Exception, e:
        log_warning('set_capwapc get exception {}'.format(repr(e)))
        return False
    return True

def get_capwapc():
    """" get capwapc """
    capwapc_data={}
    try:
        value=ubus.call("uci", "get", {"config":"capwapc","section":"server"})
        capwapc_data=value[0]['values']
    except Exception, e:
        log_warning('get_capwapc get exception {}'.format(repr(e)))
        capwapc_data={}
    return capwapc_data

def get_productinfo():
    """" get productinfo """
    try:
        value=ubus.call("uci", "get", {"config":"productinfo","section":"productinfo"})
        productinfo_data=value[0]['values']
    except Exception, e:
        log_warning('get_productinfo get exception {}'.format(repr(e)))
        productinfo_data={}
    return productinfo_data

def get_whole_conf_path():
    global config_conf_file
    return config_conf_file

def get_whole_conf_bak_path():
    global config_conf_file
    return "{}_bak".format(config_conf_file)

def set_whole_confinfo(str):
    with open(config_conf_file, 'w+', 0) as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        with open("{}_bak".format(config_conf_file), 'w+', 0) as ff:
            ff.truncate()
            ff.write(f.read())
            ff.flush()
        f.seek(0,0)
        f.truncate()
        f.write(str)
        f.flush()
    try:
        confinfo_data = json.loads(str, encoding='utf-8')
    except Exception as _:
        confinfo_data = {}
    return confinfo_data

def rollback_whole_confinfo():
    with open(config_conf_file, 'w+', 0) as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        with open("{}_bak".format(config_conf_file), 'r') as ff:
            str = ff.read()
        f.truncate()
        f.write(str)
        f.flush()
    try:
        confinfo_data = json.loads(str, encoding='utf-8')
    except Exception as _:
        confinfo_data = {}
    return confinfo_data

def get_whole_confinfo():
    with open(config_conf_file, 'r') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        str = f.read()
    try:
        confinfo_data = json.loads(str, encoding='utf-8')
    except Exception as _:
        confinfo_data = {}
    return confinfo_data

def get_ddns_status(provider):
    try:
        cmd = "{} {}".format(const.OKOS_DDNS_STATUS_SCRIPT, provider)
        pid = Popen(cmd, stdout=PIPE, shell=True)
        s = pid.communicate()[0]
        s.strip('\n')
        ddns_status_data = json.loads(s, 'utf-8')
    except Exception, e:
        log_warning('get_ddns_status get exception {}'.format(repr(e)))
        ddns_status_data = None
    return ddns_status_data

def get_file_md5sum(file_name):
    """" fetch productinfo """
    try:
        cmd = "md5sum {file_name} | awk '{{print $1}}' 2>/dev/null".format(file_name=file_name)
        pid = Popen(cmd, stdout=PIPE, shell=True)
        s = pid.communicate()[0]
        md5sum = s.strip('\n')
    except Exception, e:
        log_warning('get_file_md5sum get exception {}'.format(repr(e)))
        md5sum = ""
    return md5sum

def get_redirector_key(salt, mac):
    """" fetch redirector key """
    try:
        cmd = "echo -n \"{_salt}{_mac}\" | md5sum | awk '{{print $1}}'".format(_salt=salt, _mac=mac)
        pid = Popen(cmd, stdout=PIPE, shell=True)
        s = pid.communicate()[0]
        key = s.strip('\n')
    except Exception, e:
        log_warning('get_redirector_key get exception {}'.format(repr(e)))
        key = ""
    return key


def post_url(url, param_data=None, json_data=None, files=None, debug=False):
    if debug:
        log_debug('post to {url}'.format(url=url))
        log_debug('parameters :{param_data}'.format(param_data=param_data))
        log_debug('json body :{json_data}'.format(json_data=json_data))

    op = json_data.setdefault('operate_type', 0)

    for i in range(1,4):
        try:
            response = requests.post(url, params=param_data, json=json_data, files=files, timeout=10)
            if response.status_code == 200:
                data = response.json()
                debug and log_debug('<operate_type:{op}> response:{status}, json:{json}'.format(op=op, status=response.status_code, json=data))
                return data
            else:
                log_warning('Target reply <operate_type:{op}> error : {response}\n'.format(response=response, op=op))
        except Exception, e:
            time.sleep(1)
            log_warning("<operate_type:{op}> requests err {e}, time:{i}".format(e=repr(e), i=i, op=op))
            continue
    return {}


def get_url(url, param_data=None, json_data=None, debug=False):
    if debug:
        log_debug('url:{url}'.format(url=url))
        log_debug('param_data:{param_data}'.format(param_data=param_data))
        log_debug('json_data:{json_data}'.format(json_data=json_data))
    i = 0
    while i < 3:
        try:
            response = requests.get(url, params=param_data, json=json_data, timeout=5)
        except Exception, e:
            i = i + 1
            time.sleep(1)
            log_warning("requests err {}, time:{}".format(repr(e), i))
            continue
        break
    if i >= 3:
        return None
    log_debug('response:{reponse}'.format(response=response))
    if response.status_code == 200:
        try:
            return response.json()
        except Exception, e:
            log_warning('get_url get exception {}'.format(repr(e)))
            return None
    else:
        return None

def daemonlize(pid_file):
    # 1. daemonlize
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, e:
        log_err("fork #1 failed: %d (%s)" %
                  (e.errno, e.strerror))
        sys.exit(1)
    # decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)
    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent, print eventual PID before
            log_info("Daemon PID %d" % pid)
            with open(pid_file, 'w+') as f:
                f.write('{pid}'.format(pid=pid))
            sys.exit(0)
    except OSError, e:
        log_err("fork #2 failed: %d (%s)" % (e.errno,
                                             e.strerror))
        sys.exit(1)
'''
def netmask_int_to_a(v):
    netmask = socket.inet_ntoa(struct.pack('!I', (1<<32)-(1<<(32-v))))
    return netmask
'''
class MacAddress(object):
    ''' Utilize to check mac address format and formula string.'''
    mac_pattern = re.compile(r"^([a-fA-F0-9]{2})[:-]?([a-fA-F0-9]{2})[:-]?([a-fA-F0-9]{2})[:-]?([a-fA-F0-9]{2})[:-]?([a-fA-F0-9]{2})[:-]?([a-fA-F0-9]{2})$")
    def __init__(self, mac):
        super(MacAddress, self).__init__()
        self.mac = self._format_mac(mac)

    def _format_mac(self, mac, sep=''):
        content = MacAddress.mac_pattern.match(mac.lower())
        return content and sep.join(('{:02x}'.format(int(c, 16)) for c in content.groups()))

    @property
    def output(self):
        return self._format_mac(self.mac, '-')

def dev2vlan(dev):
    '''
    'eth0.300' => (eth0, 300)
    '''
    t = dev.split('.')
    len(t) == 1 and t.append('0')
    return t

def clients_output_fmt(x, ts=None):
    ifname, vlan = dev2vlan(x['device'])
    return {
        'state': x.setdefault('state', 0),
        'mac': x['mac'],
        'ip': x['ip'],
        'timestamp': ts or x.setdefault('timestamp', 0),
        'vlan': vlan,
        'interface_name': ifname,
    }
