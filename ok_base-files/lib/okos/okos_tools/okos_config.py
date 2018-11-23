from constant import const
import fcntl
import json

class OkosConfig(object):
    '''
    Class to control config save/get/rollback.
    '''
    def __init__(self, conf_file=''.join([const.CONFIG_DIR, const.CONFIG_CONF_FILE]), debug=False):
        super(OkosConfig, self).__init__()
        self.conf_file = conf_file
        self.bak_file = "{}_bak".format(self.conf_file)
        self.debug=debug

    def _generate_conf_data(self, json_str):
        try:
            conf_data = json.loads(json_str, encoding='utf-8')
        except Exception as _:
            conf_data = {}
        conf_data.setdefault('config_version', 0)
        return conf_data

    @property
    def whole_conf_path(self):
        return self.conf_file
    @property
    def whole_conf_bak_path(self):
        return "{}_bak".format(self.conf_file)
    
    def get_config(self):
        with open(self.conf_file, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            json_str = f.read()
        return self._generate_conf_data(json_str)

    def set_config(self, json_str):
        with open(self.conf_file, 'w+', 0) as ori:
            fcntl.flock(ori.fileno(), fcntl.LOCK_EX)
            with open(self.bak_file, 'w+', 0) as bak:
                bak.truncate()
                bak.write(ori.read())
                bak.flush()
            ori.seek(0,0)
            ori.truncate()
            ori.write(json_str)
            ori.flush()
        return self._generate_conf_data(json_str)

    def rollback_config(self):
        with open(self.conf_file, 'w+', 0) as ori:
            fcntl.flock(ori.fileno(), fcntl.LOCK_EX)
            with open(self.bak_file, 'r') as bak:
                json_str = bak.read()
            ori.truncate()
            ori.write(json_str)
            ori.flush()
        return self._generate_conf_data(json_str)
