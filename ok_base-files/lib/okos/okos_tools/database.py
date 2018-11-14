import sqlite3
from okos_tools import log_debug, log_err, MacAddress

class ArpDb(object):
    DBNAME = '/tmp/run/arp_table.db'
    DESC = 'ARP Cache Database'
    TABLE_NAME = 'arptable'
    def __init__(self, debug=False):
        self.debug = debug
        super(ArpDb, self).__init__()
        
    def __enter__(self):
        self.conn = sqlite3.connect(ArpDb.DBNAME)
        self.cur = self.conn.cursor()
        self.debug and log_debug('[%s] <%s> - connected -' % (ArpDb.DESC, ArpDb.DBNAME))
        return self
    def __exit__(self, et, v, tb):
        self.conn.close()
        self.debug and log_debug('[%s] <%s> - closed -' % (ArpDb.DESC, ArpDb.DBNAME))
        if et:
            log_err('[%s] exception :> %s >< %s <%s:%s>' % (ArpDb.DESC, et, v, tb.tb_frame.f_code.co_filename, tb.tb_lineno))
            log_err('[%s] access - failed -' % (ArpDb.DESC, ))
        else:
            self.debug and log_debug('[%s] access - done -' % (ArpDb.DESC, ))
        return True
    
    def create_table(self, sql=None):
        """ create a table from the create_table_sql statement
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        sql = sql or """CREATE TABLE IF NOT EXISTS {tb_name} (
                                mac char(12) PRIMARY KEY,
                                ipaddr text NOT NULL,
                                device text NOT NULL
                                );""".format(tb_name=ArpDb.TABLE_NAME)
        self.cur.execute(sql)
        log_debug('[%s] <%s> created by "%s"' % (ArpDb.DESC, ArpDb.DBNAME, sql))
    
    def get_all(self):
        '''return all the arp entries from database
        :return: a list of dict {'mac':..., 'ip':..., 'device':...}
        '''
        sql = '''SELECT mac,ipaddr,device FROM {tb_name}'''.format(tb_name=ArpDb.TABLE_NAME)
        self.cur.execute(sql)
        res = self.cur.fetchall()
        return [{'mac':r[0], 'ip':r[1], 'device':r[2]} for r in res]

    def update_all(self, arps):
        ''' update all the arp entris in the database
        :param arps: a list of dict {'mac':..., 'ip':..., 'device':...}
        '''
        arps = [(a['mac'], a['ip'], a['device']) for a in arps]
        self.conn.execute('DELETE from {tab}'.format(tab=ArpDb.TABLE_NAME))
        update = lambda e: self.conn.execute("INSERT INTO {tab} (MAC, IPADDR, DEVICE) VALUES(?,?,?)".format(tab=ArpDb.TABLE_NAME), e)
        map(update, arps)
        self.conn.commit()
        self.debug and log_debug('[%s] insert %s into db <%s>' % (ArpDb.DESC, arps, ArpDb.TABLE_NAME))
