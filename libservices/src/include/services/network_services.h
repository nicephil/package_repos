#ifndef __NETWORK_SERVICES_H_
#define __NETWORK_SERVICES_H_
#include <arpa/inet.h>

#define NETWORK_CFG_PACKAGE "network"
#define NETWORK_SECTION_LAN "lan"
#define NETWORK_OPTION_DEVICE "device"
#define NETWORK_OPTION_IFNAME "ifname"
#define NETWORK_OPTION_PROTO "proto"
#define NETWORK_OPTION_TYPE "type"

typedef struct interface_info
{
    int id;
    unsigned char type;
    unsigned char enable;
    unsigned char nat_enable;
    unsigned char dns_count;
    char address[33];
    char netmask[33];
    char dns_server[3][33];
    char default_address[33];
    char default_netmask[33];
    char pppoe_user[65];
    char pppoe_pass[65];
    char pppoe_acname[65];
    char pppoe_servicesname[65];
    char pppoe_mtu[65];
    char desc[81];
}interface_info;

extern int get_manage_ifinfo(interface_info *info);
extern int network_set_enable(const char *name, int enable);

#endif /* __NETWORK_SERVICES_H_ */
