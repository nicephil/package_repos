#!/usr/bin/python

from subprocess import Popen, PIPE
import syslog
from socket import *


def get_mac(iface):
    """ fetch the mac address of specified iface """

    try:
        with open('/sys/class/net/'+iface+'/address') as f:
            mac = f.readline()
    except:
        mac = ""

    if len(mac) == 0:
        if iface == "br-lan1":
            mac = "FC:AD:0F:09:27:A0"
        elif iface == "ath01":
            mac = "06:AD:0F:09:27:A0"
        else:
            mac = "00:11:22:33:44:55"

    return mac[0:17]

def get_ssid(ath):
    """" fetch the ssid of specified ath iface """
    try:
        stid = ath[4]
        pid = Popen(["uci", "-q", "get",
                     "wlan_service_template.ServiceTemplate" + stid +
                     ".ssid"], stdout=PIPE)
        s = pid.communicate()[0]
        ssid = s.strip('\n')
    except:
        ssid = ""
    if len(ssid) == 0:
        ssid = "TIparkGuest-llwang"
    return ssid

def get_authen(ath):
    """" fetch the autentication of specified ath iface """
    try:
        stid = ath[4]
        pid = Popen(["uci", "-q", "get",
                     "wlan_service_template.ServiceTemplate" + stid +
                     ".authentication"], stdout=PIPE)
        s = pid.communicate()[0]
        authen = s.strip('\n')
    except:
        authen = ""
    if len(authen) == 0:
        authen = "ppsk"
    return authen

def get_portalscheme(ath):
    """" fetch the portalscheme of specified ath iface """
    try:
        stid = ath[4]
        pid = Popen(["uci", "-q", "get",
                     "wlan_service_template.ServiceTemplate" + stid +
                     ".portal_scheme"], stdout=PIPE)
        s = pid.communicate()[0]
        portalscheme = s.strip('\n')
    except:
        portalscheme = ""
    if len(portalscheme) == 0:
        # portalscheme = "fa99d0a5841d48659a5afcbaf4a31a73_1006"
        pass
    return portalscheme


def get_domain():
    """ try to get domain from system.domain.domain """
    try:
        pid = Popen(["uci", "-q", "get",
                     "system.domain.domain"], stdout=PIPE)
        s = pid.communicate()[0]
        domain = s.strip('\n')
    except:
        domain = ""

    if len(domain) == 0:
        # domain = "fa99d0a5841d48659a5afcbaf4a31a73"
        pass

    return domain


def get_auth_url():
    """ try to get auth_url from system.auth_url.auth_url """
    try:
        pid = Popen(["uci", "-q", "get",
                     "system.auth_url.auth_url"], stdout=PIPE)
        s = pid.communicate()[0]
        auth_url = s.strip('\n')
    except:
        auth_url = ""

    if len(auth_url) == 0:
        #auth_url = "http://139.196.188.253/auth/device/client"
        pass

    return auth_url


def mac_to_byte(mac):
    mac_tmp = mac.split(':')
    mac_byte = ''
    for _, item in enumerate(mac_tmp):
        mac_byte += chr(int(item, base=16))
    return mac_byte

def okos_sta_log_info(msg):
    syslog.openlog("200-STA", syslog.LOG_NDELAY, syslog.LOG_USER)
    syslog.syslog(syslog.LOG_INFO, msg)
    syslog.closelog()
    syslog.openlog("clientevent", syslog.LOG_NDELAY, syslog.LOG_USER)

def okos_sta_log_warn(msg):
    syslog.openlog("200-STA", syslog.LOG_NDELAY, syslog.LOG_USER)
    syslog.syslog(syslog.LOG_WARNING, msg)
    syslog.closelog()
    syslog.openlog("clientevent", syslog.LOG_NDELAY, syslog.LOG_USER)

def sendeth(src, dst, eth_type, payload, interface = "eth0"):
    """Send raw Ethernet packet on interface."""

    assert(len(src) == len(dst) == 6) # 48-bit ethernet addresses
    assert(len(eth_type) == 2) # 16-bit ethernet type

    s = socket(AF_PACKET, SOCK_RAW)

    # From the docs: "For raw packet
    # sockets the address is a tuple (ifname, proto [,pkttype [,hatype]])"
    s.bind((interface, 0))
    ret = s.send(src + dst + eth_type + payload)
    s.close()
    return ret

def sendether(src):
    src = src.replace(':','').decode('hex')
    dst="\xFF\xFF\xFF\xFF\xFF\xFF"
    eth_type="\x7A\x05"
    payload="hello"
    return sendeth(dst, src, eth_type, payload)

if __name__ == '__main__':
    print get_mac("br-lan1")
    print get_mac("ath10")
    print get_ssid("ath00")
    print get_portalscheme("ath10")
    print("Sent %d-byte Ethernet packet on eth0" %
          sendether("FA:ED:FA:CE:BE:EF"))
