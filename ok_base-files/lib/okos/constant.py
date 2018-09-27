import const

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


const.DEV_DDNS_STATUS_RESP_OPT_TYPE = 2006

const.DEV_REBOOT_OPT_TYPE = 2007

# WebUI conf query
const.DEV_WEBUI_CONF_REQ_OPT_TYPE = 2009
const.DEV_WEBUI_CONF_RESP_OPT_TYPE = 2010

#
const.DEV_CONF_PORT_TYPE = {'none':-1, 'wan':0, 'lan':1, 'bridge':2, }
const.DEV_CONF_PORT_MODE = {'full':1, 'half':2}
const.DEV_CONF_PORT_STATE = {'up':1, 'down':0}

const.CONFIG_BIN_DIR = '/lib/okos/bin/'
