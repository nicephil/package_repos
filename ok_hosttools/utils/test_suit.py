#!/usr/bin/python

import thread
import time
import random
import os

class Client(object):
    def __init__(self, mac, ip, ppsk_key=""):
        self.mac = mac
        self.ip = ip
        self.name = mac
        self.ppsk_key = ppsk_key

    def set_event(self, ath, event):
        self.ath = ath
        self.event = event

    def get_cmdmsg(self):
        if self.event == 'AP-STA-CONNECTED' or self.event == 'AP-STA-DISCONNECTED':
            self.cmd_msg = '/lib/okos/wifievent.sh %s %s %s %s' % (self.ath, self.event, self.mac, self.ppsk_key)
        elif self.event == 'STA-IP-CHANGED':
            self.cmd_msg = 'sqlite3 /tmp/stationinfo.db \'BEGIN TRANSACTION;UPDATE STAINFO set IPADDR="%s" WHERE MAC="%s";COMMIT\';echo "===>$?";echo %s %s %s_%s > /tmp/wifievent.pipe' % (self.ip, self.mac, self.ath, self.mac, "STA-IP-CHANGED", self.ip)
        return self.cmd_msg

class AP(object):
    def __init__(self, ip, testmode):
        self.ip = ip
        self.testmode = testmode
        self.client_dict = {}
        self.init_clients()

    def init_clients(self):
        i = 0
        while i <= 200:
            # 1. generate random client
            mac = "00:11:22:33:44:%02x" % i
            ip = "192.168.1.%d" % i
            ppsk_key = "904F690F09A89566AA39DB54CAE83BFB36B28AB49161E29DA4DA45D8DDEB60%02x" % i
            self.client_dict[mac] = Client(mac, ip, ppsk_key)
            i = i + 1

    def exec_cmdmsg(self, cmdmsg):
         # 1. send connected event
        if self.testmode == 'onpc':
            os.system('ssh root@%s "%s"' % (self.ip, cmdmsg))
        elif self.testmode == 'onap':
            os.system("%s" % cmdmsg)
        print self.testmode, cmdmsg

    def get_stats(self):
        if self.testmode == 'onpc':
            os.system('ssh root@%s "%s"' % (self.ip, "/lib/okos/list_client.sh;sqlite3 /tmp/stationinfo.db 'select * from stainfo';echo 'xxx';sqlite3 /tmp/statsinfo.db 'select * from statsinfo'"))
        elif self.testmode == 'onap':
            os.system("%s" % "/lib/okos/list_client.sh;sqlite3 /tmp/stationinfo.db 'select * from stainfo';echo 'xxx';sqlite3 /tmp/statsinfo.db 'select * from statsinfo'")

    def test1(self):
        for mac,client in self.client_dict.iteritems():
            client.set_event('ath10', 'AP-STA-CONNECTED')
            thread.start_new_thread(self.exec_cmdmsg, (client.get_cmdmsg(),))
            client.set_event('ath10', 'STA-IP-CHANGED')
            thread.start_new_thread(self.exec_cmdmsg, (client.get_cmdmsg(),))
            client.set_event('ath10', 'AP-STA-DISCONNECTED')
            thread.start_new_thread(self.exec_cmdmsg, (client.get_cmdmsg(),))
        time.sleep(1)
        #self.get_stats()
        time.sleep(5)
        print "==================="
        #self.get_stats()

def main():
    ap = AP("192.168.1.195", "onap")
    ap.test1()

if __name__ == '__main__':
    main()
