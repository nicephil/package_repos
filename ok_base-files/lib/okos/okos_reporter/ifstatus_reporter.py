

from okos_tools import *
from constant import const
import re

class IfStateEnv(ExecEnv):
    def __init__(self, desc, debug=False):
        super(IfStateEnv, self).__init__('Interface State', desc=desc, raiseup=False, debug=debug)



class IfStatusReporter(Poster):
    def __init__(self, mailbox, operate_type=const.DEV_IF_STATUS_RESP_OPT_TYPE, name='IfStatusTimer', interval=60, debug=False):
        super(IfStatusReporter, self).__init__(name, interval, mailbox, operate_type, repeated=True, debug=debug)
        self.debug = debug
    def handler(self, *args, **kwargs):
        '''
        This timer will be self-kicked off for every 60 seconds.
        '''
        phy_ifnames = const.PORT_MAPPING_PHY
        cfg_ifnames = const.PORT_MAPPING_CONFIG

        '''
                    |  WAN   |  WAN1  |  WAN2  | LAN4053
        config: ----+--------+--------+--------+---------
        enable      |   y    |   n    |   n    |   y
        cable       |   on   |  off   |  off   |  off
        device: ----+--------+--------+--------+---------
        up          |   y    |   y    |   y    |   y
        carrier     |   y    |   n    |   n    |   n     # physical state
        speed       | 1000F  |  -1F   |  -1F   |  -1F
        mtu         |  1492  |  1500  |  1500  |  1500
        mac addr    |        |        |        |
        interface: -+--------+--------+--------+---------
        up          |   y    |   n    |   n    |   y     # Admin state
        pending     |   n    |   n    |   n    |   n
        available   |   y    |   y    |   y    |   y
        dynamic     |   n    |   n    |   n    |   n
        uptime      |  3705  |   -    |   -    |  4036
        l3_device   |  eth0  |   -    |   -    |  eth3
        device      |  eth0  |  eth1  |  eth2  |  eth3
        proto       | static |  none  |  none  | static
        ip addresses|   y    |   -    |   -    |   y
        dnss        |   y    |   -    |   -    |   y
        routes      |   y    |   -    |   -    |   y
        '''
        with IfStateEnv('Aquire State and Config from ubus', debug=self.debug):
            # {'eth0':...}
            #devices = ubus.call('network.device','status', {})[0]
            #devices = {k:v for k,v in devices.iteritems() if k.startswith('eth')}
            devices = {k:v for k,v in UciStatus('network.device').iteritems() if k in phy_ifnames}
            #interfaces = {d: ubus.call('network.interface.' + phy_ifnames[d]['ifname'], 'status', {})[0] for d in devices}
            interfaces = {d: UciStatus('network.interface.' + phy_ifnames[d]['ifname']).dump() for d in devices}
            for ifx,c in devices.iteritems():
                c.update(interfaces[ifx])
            interfaces = devices
            #network_conf = ubus.call('uci', 'get', {'config':'network'})[0]['values']
            network_conf = UciConfig('network')
            network_conf = {cfg_ifnames[k]['phy']:v for k,v in network_conf.iteritems() if k in cfg_ifnames}
            #dhcp_conf = ubus.call('uci', 'get', {'config':'dhcp'})[0]['values']
            dhcp_conf = UciConfig('dhcp')
            dhcp_conf = {cfg_ifnames[k]['phy']:v for k,v in dhcp_conf.iteritems() if k in cfg_ifnames}

        ip_types = {'dhcp': 0, 'static':1, 'pppoe': 2}
        with IfStateEnv('Create Basic interfaces infor', debug=self.debug):
            ifs_state = [{
                    'ifname': ifname,
                    'name': phy_ifnames[ifname]['logic'],
                    'type': phy_ifnames[ifname]['type'],
                    #'mac': data['macaddr'],
            } for ifname in phy_ifnames]

        def update_ifs_state(ifs_next):
            for ifname, ifx in ifs_state.iteritems():
                if ifname in ifs_next:
                    ifx.update(ifs_next[ifname])

        def abstract_link_status(ifx_output):
            ifx_input = interfaces[ifx_output['ifname']]
            ifx_output['state'] = ifx_output['physical_state'] = ifx_input.setdefault('carrier', False) and 1 or 0
            ifx_output['proto'] = ifx_input.setdefault('proto','none')
            ifx_output['status'] = ifx_output['proto'] != 'none' and 1 or 0 # It's admin state
            ifx_output['ip_type'] = ip_types.setdefault(ifx_output['proto'], -1)
        with IfStateEnv('Link Statue', debug=self.debug):
            map(abstract_link_status, ifs_state)

        p = re.compile('^([0-9]+)([FH])$')
        def abstract_speed(ifx_output):
            ifx_input = interfaces[ifx_output['ifname']]
            if ifx_output['status'] and 'uptime' in ifx_input:
                ifx_output['uptime'] = ifx_input['uptime']
            if ifx_output['physical_state'] and 'speed' in ifx_input:
                res = p.match(ifx_input['speed'])
                if res:
                    bandwidth, duplex = res.groups()
                    ifx_output['bandwidth'] = bandwidth
                    ifx_output['duplex'] = duplex == 'F' and 1 or 2
        with IfStateEnv('Interface speed', debug=self.debug):
            map(abstract_speed, ifs_state)

        def abstract_ip_setting(ifx_output):
            ifname = ifx_output['ifname']
            with IfStateEnv('IP Setting on %s' % (ifname), debug=self.debug):
                ifx_input = interfaces[ifname]
                if ifx_output['status']:
                    ifx_output['dnss'] = ','.join([dns for dns in ifx_input.setdefault('dns-server', [])])
                    ifx_output['ips'] = [{'ip':ip['address'], 'netmask':ip['mask']} for ip in ifx_input.setdefault('ipv4-address',[])]
                    if ifx_output['type'] == const.DEV_CONF_PORT_TYPE['wan']:
                        defaultroutes = [r['nexthop'] for r in ifx_input.setdefault('route',[]) if r['target'] == '0.0.0.0']
                        if defaultroutes:
                            ifx_output['gateway'] = defaultroutes[0]
        map(abstract_ip_setting, ifs_state)

        def abstract_pppoe(ifx_output):
            ifname = ifx_output['ifname']
            with IfStateEnv('pppoe on %s' % (ifname), debug=self.debug):
                if ifx_output['type'] == const.DEV_CONF_PORT_TYPE['wan'] and ifx_output['proto'] == 'pppoe' and ifx_output['status']:
                    ifx_input = network_conf[ifname]
                    ifx_output['pppoe_username'] = ifx_input['username']
                    ifx_output['pppoe_password'] = ifx_input['password']
        map(abstract_pppoe, ifs_state)

        def abstract_dhcp_server(ifx_output):
            ifname = ifx_output['ifname']
            with IfStateEnv('DHCP server on %s' % (ifname), debug=self.debug):
                if ifx_output['status'] and ifx_output['type'] == const.DEV_CONF_PORT_TYPE['lan']:
                    ifx_input = dhcp_conf[ifname]
                    ifx_output['dhcp_start'] = ifx_input['start']
                    ifx_output['dhcp_limit'] = ifx_input['limit']
        map(abstract_dhcp_server, ifs_state)


        #with open('/tmp/if_state.tmp','w+') as f:
        #    json.dump(ifs_state,f)

        return {'list': ifs_state}

