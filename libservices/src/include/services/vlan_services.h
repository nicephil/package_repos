#ifndef __VLAN_SERVICES_H_
#define __VLAN_SERVICES_H_

#define VLAN_MAX_COUNT 32
#define VLAN_CFG_PACKAGE "network"
#define VLAN_INTERFACE_PREFIX "vlan"
#define VLAN_PORT_CFG_PACKAGE "vlan_port"

enum VLAN_PORT_TYPE {
    VLAN_PORT_TYPE_ACCESS = 0,
    VLAN_PORT_TYPE_TRUNK,
    VLAN_PORT_TYPE_HYBRID,

    VLAN_PORT_TYPE_MAX
};

enum IP_TYPE
{
    IP_TYPE_DHCP = 0,
    IP_TYPE_STATIC,
    IP_TYPE_PPPOE,
    IP_TYPE_NONE
};

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

typedef struct vlan_interface_info
{
    int count;
    interface_info info[20];   
} vlan_interface_info;



extern int vlan_list_id(int **idlist);
extern int vlan_create(int vlanid, int endid);
extern int vlan_destroy(int vlanid, int endid);
extern int vlan_undo_name(int vlanid);
extern int vlan_set_name(int vlanid, const char *name);
extern int vlan_undo_desc(int vlanid);
extern int vlan_set_desc(int vlanid, const char *desc);
extern void vlan_list_id_free(int **idlist);
extern int vlan_set_type(const char * port_name, int type);
extern int vlan_set_pvid(const char * port_name, int pvid, int type);
extern int vlan_permit_all(const char * name);
extern int vlan_undo_permit_all(const char * name);
extern int vlan_permit(const char * name, int start, int end);

extern int vlan_get_ifname(int vlanid, char *ifname);
extern int vlan_get_dialer_info(vlan_interface_info **info);


extern int dialer_undo(const char *ifname, int type);
extern int dialer_set_dhcp(const char *ifname);
extern int dialer_static_set_ipv4(const char *ifname, const char *ip,
        const char *netmask, const char *gateway);
#endif /* __VLAN_SERVICES_H_ */
