#!/usr/bin/python

import json
import os
import time
import random
import time
import vici
import sqlite3
import status_mgr

def write_pipe(str):
    with open("/opt/oakridge/okos/okos_mgr.pipe", 'w') as f:
        f.write(str)

def contract_confrequst():
    data_json = {
        "config_version":1,
        "mgmt": {
            "system" : {
                "hostname":"vpnserver{}".format(random.randint(300,4000))
            }
        },
        "network" : {
            "ddnss": [ {
                "provider" : "3322.org",
                "hostname" : "ak74.f3322.net",
                "username" : "root",
                "password" : "wangleih{}".format(random.randint(100,200))
            }]
        }
    }
    msg_list = {}
    msg_list['operate_type'] = 2001
    msg_list['cookie_id'] = 2222
    msg_list['timestamp'] = int(time.time())
    msg_list['data'] = json.dumps(data_json)
    msg = {}
    msg['mac'] = '11:22:33:44:55:66'
    msg['list'] = []
    msg['list'].append(msg_list)
    return json.dumps(msg)

def main():
    vs = vici.Session()
    sas_list = vs.list_sas()
    for k in sas_list:
        for k1, v1 in k.items():
            print v1
            for k2, v2 in v1.items():
                print v2
                if k2 == "child-sas":
                    for k3, v3 in v2.items():
                        print v3

    print 'xxxx'
    sconn = sqlite3.connect("/tmp/stationinfo.db")
    cu = sconn.cursor()
    cu.execute("select * from STAINFO")
    cu_list = cu.fetchall()
    print  cu_list

    return 0
    while True:
        str = contract_confrequst()
        print str
        write_pipe(str)
        time.sleep(5)

if __name__ == '__main__':
    main()
