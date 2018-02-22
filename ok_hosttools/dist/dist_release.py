#!/usr/bin/env python

import argparse
import os
import md5
import requests
import pprint

class ToolTest(object):
    def __init__(self, cmd, url):
        self.cmd = cmd
        self.url = url

    def curl(self, method, params=None, body=None):
        params = params and '&'.join(('='.join((str(k),str(v))) for k,v in params.iteritems())) or ''
        params = params and '?'+ params or ''
        body = body and '{body}'.format(body=body).replace("'",'"') or ''
        body = body and "-d '{body}'".format(body=body) or ''
        cmd = self.cmd.format(
                method=method,
                url=self.url,
                params=params,
                body=body
                )
        print cmd
        print '--->'
        return bool(os.system(cmd) == 0)

    def get(self, params=None, body=None):
        return self.curl('GET', body=body, params=params)
    def post(self, params=None, body=None):
        return self.curl('POST', body=body, params=params)
    def delete(self, params=None, body=None):
        return self.curl('DELETE', body=body, params=params)

class ToolRequest(object):
    def __init__(self, url):
        self.url = url

    def curl(self, response):
        print response.url
        print '--->[status code:{rc}]'.format(rc=response.status_code)
        if response.status_code == 200:
            pprint.pprint(response.json())
        else:
            print response.content
        return True

    def get(self, params=None, body=None):
        return self.curl(requests.get(self.url, params=params, json=body))
    def post(self, params=None, body=None):
        return self.curl(requests.post(self.url, params=params, json=body))
    def delete(self, params=None, body=None):
        return self.curl(requests.delete(self.url, params=params, json=body))

class ApiServer(object):
    def __init__(self, target, port):
        self.target = target
        self.port = port
        self.url = 'http://{target}:{port}{path}'.format(target=target, port=port, path=self.path)
        self.cmd = 'curl -H "Content-Type: application/json" -X {method} {url}{params} {body}'
        self.tool = ToolRequest(self.url)
        #self.tool = ToolCurl(self.cmd, self.url)

        
class DeviceRegister(ApiServer):
    def __init__(self, target, port):
        self.path = '/redirector/v1/device/register/'
        super(DeviceRegister,self).__init__(target, port)

    def gen_key(self, mac):
        m = md5.new("Nobody knows")
        m.update(mac)
        return m.hexdigest()

    def query(self, device, dev_type):
        payload = {'device':device, 'version':'1.0', 'device_type':dev_type}
        params = {'key':self.gen_key(device)}
        return self.tool.post(params=params, body=payload)

            
class OakmgrRegister(ApiServer):
    def __init__(self, target, port):
        self.path = '/redirector/v1/oakmgr/register/'
        self.params = {}
        super(OakmgrRegister,self).__init__(target, port)

    def show(self, oakmgr=None, macs=None):
        if oakmgr is not None:
            self.params['oakmgr'] = oakmgr
            return self.tool.get(params=self.params)
        if macs:
            self.params['devices'] = macs
            return self.tool.get(params=self.params)
        else:
            return self.tool.get()

    def query(self, macs):
        payload = {'action':'query', 'oakmgr':'', 'devices':macs}
        return self.tool.post(body=payload)

    def add(self, macs, oakmgr, port, cookie, override):
        payload = {'action':'add', 'oakmgr':oakmgr, 'devices':macs}
        if cookie is not None:
            payload['cookie'] = cookie
        if override:
            payload['override'] = 1
        if port:
            payload['port'] = port
        return self.tool.post(body=payload)

    def remove(self, macs, oakmgr):
        payload = {'action':'remove', 'oakmgr':oakmgr, 'devices':macs}
        return self.tool.post(body=payload)

    def remove_all(self):
        self.params['key'] = '31415926'
        return self.tool.delete(params=self.params)

class VersionRelease(ApiServer):
    def __init__(self, target, port):
        self.path = '/redirector/v1/version/release/'
        self.params = {'key':1}
        super(VersionRelease,self).__init__(target, port)

    def add(self, md5, url, dev_type, comment):
        payload = {'action':'add_image', 'md5':md5, 'url':url, 'type':dev_type}
        if comment is not None:
            payload['comment'] = comment
        return self.tool.post(params=self.params, body=payload)

    def delete(self, md5, comment):
        payload = {'action':'delete_image','md5':md5}
        return self.tool.post(params=self.params, body=payload)

    def show(self, md5=None, devtype=None):
        if md5:
            self.params['md5'] = md5
        return self.tool.get(params=self.params)

    def remove_all(self):
        self.params['key'] = '31415926'
        return self.tool.delete(params=self.params)
    
class VersionControl(ApiServer):
    def __init__(self, target, port):
        self.path = '/redirector/v1/version/control/'
        self.params = {'key':1}
        super(VersionControl, self).__init__(target, port)

    def bind(self, md5, macs, comment):
        body = {'action':'attach_mac', 'md5':md5, 'devices':macs}
        if comment is not None:
            body['comment'] = comment
        return self.tool.post(params=self.params, body=body)

    def unbind_dev(self, md5, macs, comment):
        body = {'action':'dettach_mac', 'md5':md5, 'devices':macs}
        if comment is not None:
            body['comment'] = comment
        return self.tool.post(params=self.params, body=body)

    def unbind_ver(self, md5, comment):
        body = {'action':'dettach_all', 'md5':md5}
        if comment is not None:
            body['comment'] = comment
        return self.tool.post(params=self.params, body=body)

    def set_default(self, md5, devtype, comment):
        body = {'action':'set_default', 'md5':md5, 'type':devtype}
        if comment is not None:
            body['comment'] = comment
        return self.tool.post(params=self.params, body=body)
    
    def unset_default(self, md5, devtype, comment):
        body = {'action':'unset_default', 'md5':md5, 'type':devtype}
        if comment is not None:
            body['comment'] = comment
        return self.tool.post(params=self.params, body=body)
    
    def add_cookie(self, md5, cookie):
        body = {'action':'add_cookie', 'md5':md5, 'cookie':cookie}
        return self.tool.post(params=self.params, body=body)

    def del_cookie(self, md5, cookie):
        body = {'action':'del_cookie', 'md5':md5, 'cookie':cookie}
        return self.tool.post(params=self.params, body=body)

    def show(self, md5=None, devtype=None):
        if md5:
            self.params['md5'] = md5
        if devtype:
            self.params['type'] = devtype[0]
        return self.tool.get(params=self.params)

def main(args):
    #print args
    if args.action == 'register':
        svr = OakmgrRegister(args.target, args.port)
        if args.show:
            return svr.show(macs=args.macs, oakmgr=args.oakmgr)
        elif args.query and args.macs:
            return svr.query(args.macs)
        elif args.add and args.oakmgr and args.macs:
            return svr.add(args.macs, args.oakmgr, args.svrport, args.cookie, args.override)
        elif args.delete and args.oakmgr and args.macs:
            return svr.remove(args.macs, args.oakmgr)
        elif args.remove:
            return svr.remove_all()
        else:
            return
    elif args.action == 'device':
        svr = DeviceRegister(args.target, args.port)
        if args.query and args.macs and args.devtype:
            return svr.query(args.macs[0], args.devtype[0])
        else:
            return
    elif args.action == 'release':
        svr = VersionRelease(args.target, args.port)
        if args.add and args.md5 and args.url and args.devtype:
            return svr.add(args.md5, args.url, args.devtype, args.comment)
        elif args.delete and args.md5:
            return svr.delete(args.md5, args.comment)
        elif args.show:
            return svr.show(args.md5, args.devtype)
        elif args.remove:
            return svr.remove_all()
        else:
            return
    elif args.action == 'deploy':
        svr = VersionControl(args.target, args.port)
        if args.bind and args.md5 and args.macs:
            return svr.bind(args.md5, args.macs, args.comment)
        elif args.unbind and args.md5 and args.macs:
            return svr.unbind_dev(args.md5, args.macs, args.comment)
        elif args.unbind and args.md5:
            return svr.unbind_ver(args.md5, args.comment)
        elif args.set_default and args.md5 and args.devtype:
            return svr.set_default(args.md5, args.devtype, args.comment)
        elif args.unset_default and args.md5 and args.devtype:
            return svr.unset_default(args.md5, args.devtype, args.comment)
        elif args.add_cookie and args.md5 and args.cookie:
            return svr.add_cookie(args.md5, args.cookie)
        elif args.del_cookie and args.md5 and args.cookie:
            return svr.del_cookie(args.md5, args.cookie)
        elif args.show:
            return svr.show(md5=args.md5, devtype=args.devtype)
        else:
            return
    else:
        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Configure Device')
    parser.add_argument('target', type=str, help='api server')
    parser.add_argument('-p', '--port', type=str, help='port number on api server',
            default='80')
    parser.add_argument('-A', '--action', choices=['register', 'device', 'release', 'deploy'], required=True,
            help='Catagory of behavior')

    parser.add_argument('-s', '--show', action='store_true', help='<register> [oakmgr][macs] | <release> [md5][devtype] | <deploy> [md5][devtype]')
    parser.add_argument('-q', '--query', action='store_true', help='<register> macs | <device> macs devtype')
    parser.add_argument('-a', '--add', action='store_true', help='<register> macs oakmgr [svrport][cookie][override] | <release> md5 url types [comment]')
    parser.add_argument('-d', '--delete', action='store_true', help='<register> oakmgr macs | <release> md5')
    parser.add_argument('-b', '--bind', action='store_true', help='<deploy> md5 macs [comment]')
    parser.add_argument('-u', '--unbind', action='store_true', help='<deploy> md5 [macs][comment]')
    parser.add_argument('-S', '--set_default', action='store_true', help='<deploy> md5 type [comment]')
    parser.add_argument('-U', '--unset_default', action='store_true', help='<deploy> md5 type [comment]')
    parser.add_argument('-c', '--add_cookie', action='store_true', help='<deploy> md5 cookie')
    parser.add_argument('-C', '--del_cookie', action='store_true', help='<deploy> md5 cookie')
    #parser.add_argument('-X', '--remove', action='store_true', help='DELETE ALL entries on register | release')

    parser.add_argument('--oakmgr', type=str, help='IP address of Oak Manager')
    parser.add_argument('--svrport', type=str, help='port of Oak Manager')
    parser.add_argument('--macs', type=str, help='MAC address of devices', nargs='+')
    parser.add_argument('--type', dest='devtype', help='device type used to query its oakmgr', nargs='+')
    parser.add_argument('--md5', help='md5 of release version',)
    parser.add_argument('--url', help='url of release version')
    parser.add_argument('--cookie', help='cookie to catagory images')
    parser.add_argument('--override', action='store_true', help='override register request')
    parser.add_argument('--comment',help='comment')
    
    #parser.add_argument()
    args = parser.parse_args()

    if main(args) is not True:
        parser.print_help()

    print ''
