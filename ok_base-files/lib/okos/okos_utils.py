#!/usr/bin/python

from subprocess import Popen, PIPE


def get_mac(iface):
    """ fetch the mac address of specified iface """
    try:
        mac = open('/sys/class/net/'+iface+'/address').readline()
    except:
        mac = "00:00:00:00:00:00"
    return mac[0:17]


def get_ssid(ath):
    """" fetch the ssid of specified ath iface """
    try:
        stid = ath[4]
        pid = Popen(["uci", "-q", "get",
                     "wlan_service_template.ServiceTemplate" + stid +
                     ".ssid"], stdout=PIPE)
        s = pid.communicate()[0]
        ssid = s
    except:
        ssid = ""
    return ssid


def get_portalscheme(ath):
    """" fetch the portalscheme of specified ath iface """
    try:
        stid = ath[4]
        pid = Popen(["uci", "-q", "get",
                     "wlan_service_template.ServiceTemplate" + stid +
                     ".portal_scheme"], stdout=PIPE)
        s = pid.communicate()[0]
        portalscheme = s
    except:
        portalscheme = ""
    return portalscheme


if __name__ == '__main__':
    print get_mac("br-lan1")
    print get_mac("ath10")
    print get_ssid("ath00")
    print get_portalscheme("ath10")
