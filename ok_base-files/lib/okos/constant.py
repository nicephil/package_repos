import const, re

const.BASE_DIR_STR = '/'
const.CONFIG_DIR_STR = './etc/'
const.SYSLOADER_DIR_STR = './sysloader/'
const.OKOS_DIR_STR = './'
const.SYSLOADER_OKOS_LIB_DIR_STR = './lib/okos/'
const.CONFIG_CAPWAPC = './capwapc.json'
const.CONFIG_CONF_FILE = './config.json'
const.OKOS_OKOS_LIB_DIR_STR = './lib/okos/'
const.OKOS_MGR_STR = './okos_mgr.py'
const.SYSLOADER_MGR_PIDFILE = './sysloader_mgr.pid'
const.OKOS_CFGDIFF_SCRIPT_STR = './cfgdiff.py'
const.OKOS_DDNS_STATUS_SCRIPT_STR = './get_ddns_status.sh'

const.BASE_DIR = const.BASE_DIR_STR

const.CONFIG_DIR = ''.join([const.BASE_DIR,const.CONFIG_DIR_STR])
const.SYSLOADER_DIR = ''.join([const.BASE_DIR, const.SYSLOADER_DIR_STR])
const.OKOS_DIR = ''.join([const.BASE_DIR, const.OKOS_DIR_STR])
const.OKOS_OKOS_LIB_DIR = ''.join([const.OKOS_DIR, const.OKOS_OKOS_LIB_DIR_STR])

const.SYSLOADER_OKOS_LIB_DIR = ''.join([const.SYSLOADER_DIR, const.SYSLOADER_OKOS_LIB_DIR_STR])

const.OKOS_CFGDIFF_SCRIPT = ''.join([const.OKOS_OKOS_LIB_DIR, const.OKOS_CFGDIFF_SCRIPT_STR])
const.OKOS_DDNS_STATUS_SCRIPT = ''.join([const.OKOS_OKOS_LIB_DIR, const.OKOS_DDNS_STATUS_SCRIPT_STR])
const.CST_IMG_TMP_FILE = '/tmp/okos.img.gz'



# redirector
const.SALT = 'Nobody knows'
const.DEFAULT_PORT = '80'
const.DEFAULT_ADDR = 'api.oakridge.io'


# init sys
const.INIT_SYS_SCRIPT_NAME = './init_sys.sh'
const.INIT_SYS_SCRIPT = ''.join([const.OKOS_OKOS_LIB_DIR, const.INIT_SYS_SCRIPT_NAME])
const.HEARTBEAT_TIME = 30
const.HEARTBEAT_DELAY = 4 * const.HEARTBEAT_TIME

# status_mgr -> collect_status priority queue
const.STATUS_Q = 'status'
# collect_status -> process_request
const.HEARTBEAT_Q = 'report'
# process_request -> conf_mgr
const.CONF_REQUEST_Q = 'conf_request'

# MSG_OPT_TYPE to NMS
const.DEV_IF_STATUS_RESP_OPT_TYPE = 2008
const.DEV_CPU_MEM_STATUS_RESP_OPT_TYPE = 12
const.DEV_INFO_OPT_TYPE = 2000

const.DEV_CONF_OPT_TYPE = 2001
const.DEV_CONF_RESP_OPT_TYPE = 2002

const.DEV_CONN_STATUS_QUREY_OPT_TYPE = 2003
const.DEV_CONN_STATUS_RESP_OPT_TYPE = 2004
const.VPN_CONN_STATUS_RESP_OPT_TYPE = 2015
const.CLIENT_ONLINE_QUERY_OPT_TYPE = 2016
const.CLIENT_ONLINE_RESP_OPT_TYPE = 2017
const.CLIENT_ONLINE_STATUS_RESP_OPT_TYPE = 2018


const.DEV_DDNS_STATUS_RESP_OPT_TYPE = 2006

const.DEV_REBOOT_OPT_TYPE = 2007

# WebUI conf query
const.DEV_WEBUI_CONF_REQ_OPT_TYPE = 2009
const.DEV_WEBUI_CONF_RESP_OPT_TYPE = 2010

# diag request
const.DEV_DIAG_REQ_OPT_TYPE = 2011
const.DEV_DIAG_RESP_OPT_TYPE = 2012

# upgrade request
const.DEV_UPGRADE_REQ_OPT_TYPE = 2013
const.DEV_UPGRADE_RESP_OPT_TYPE = 2014

#
const.DEV_CONF_PORT_TYPE = {'none':-1, 'wan':0, 'lan':1, 'bridge':2, }
const.DEV_CONF_PORT_MODE = {'full':1, 'half':2}
const.DEV_CONF_PORT_STATE = {'up':1, 'down':0}

const.CONFIG_BIN_DIR = '/lib/okos/bin/'
const.PORT_MAPPING = [
        {'type': const.DEV_CONF_PORT_TYPE['wan'], 'ifname': 'wan', 'logic': 'e0', 'phy': 'eth0'},
        {'type': const.DEV_CONF_PORT_TYPE['wan'], 'ifname': 'wan1', 'logic': 'e1', 'phy': 'eth1'},
        {'type': const.DEV_CONF_PORT_TYPE['wan'], 'ifname': 'wan2', 'logic': 'e2', 'phy': 'eth2'},
        {'type': const.DEV_CONF_PORT_TYPE['lan'], 'ifname': 'lan4053', 'logic': 'e3', 'phy': 'eth3'},
        ]

const.PORT_MAPPING_PHY = {ifx['phy']:ifx for ifx in const.PORT_MAPPING}
const.PORT_MAPPING_LOGIC = {ifx['logic']:ifx for ifx in const.PORT_MAPPING}
const.PORT_MAPPING_CONFIG = {ifx['ifname']:ifx for ifx in const.PORT_MAPPING}
const.LAN_IFACES = [p['phy'] for p in const.PORT_MAPPING if p['type'] == const.DEV_CONF_PORT_TYPE['lan']]

const.CONFIG_SECURITY_ZONE = ('TRUSTED', 'UNTRUSTED', 'DMZ', 'GUEST')

const.FMT_PATTERN = {
        'ipaddr': re.compile(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'),
        'mac': re.compile(r'^([0-9a-zA-Z]{2})[:-]?([0-9a-zA-Z]{2})[:-]?([0-9a-zA-Z]{2})[:-]?([0-9a-zA-Z]{2})[:-]?([0-9a-zA-Z]{2})[:-]?([0-9a-zA-Z]{2})$'),
        'entry_id': re.compile(r'^[a-zA-Z0-9]+_[a-zA-Z0-9_]+$'),
        'simple_id': re.compile(r'^[a-zA-Z0-9]+$'),
        'number': re.compile(r'^[0-9]+$'),
        'socket_port': re.compile(r'^([0-9]{1,5})$'),
        'socket_port_range': re.compile(r'^([0-9]{1,5})([-~:]([0-9]{1,5}))?$'),
}


############### Error Code to Oakmgr #####################
# 1 - 9999 common error code
const.COMMON_SUCCESS = 0
const.COMMON_FAILURE = 1

# 10000 - 19999 config error code

# 20000 - 29999 monitor error code
const.PPPOE_DISCOVERY_ERROR = 20001
const.PPPOE_AUTH_ERR = 20002
const.PPPOE_CAN_NOT_CONNECTED = 20003
const.CAN_NOT_GET_IP = 20004


##########################################################
