#include <stdlib.h>
#include <string.h>

#include "services/cfg_services.h"
#include "services/vlan_services.h"

static int vlan_iterator_id(struct uci_package *p, void *arg)
{
    struct uci_element *e;
    struct uci_section *s;
    int id, num = 0, *idlist = (int *)arg;

    uci_foreach_element(&p->sections, e) {
        s = uci_to_section(e);
        if (!strncmp(s->e.name, "lan", 3)) {
            sscanf(s->e.name, "lan%d", &id);
            if (id > 0) {
                idlist[num++] = id;
            }
        }
    }

    return num;
}

int vlan_list_id(int **idlist)
{
    int size, *totalid = NULL;

    size = VLAN_MAX_COUNT;
    totalid = (int *)malloc(size * sizeof(int));
    if (!totalid) {
        return -1;
    }

    size = cfg_visit_package(VLAN_CFG_PACKAGE, vlan_iterator_id, totalid);
    *idlist = totalid;
    
    return size;
}

int vlan_create(int vlanid, int endid)
{
    int i;
    char buf[20];
    char tuple[128];

    for (i = vlanid; i <= endid; ++i) {
        //network.lan1=interface
        //network.lan1.ifname='eth0.1'
        //network.lan1.type='bridge'
        //network.lan1.proto='dhcp'
        sprintf(buf, "lan%d", vlanid);
        cfg_add_section_with_name_type("network", buf, "interface");
        sprintf(tuple, "network.lan%d.ifname", vlanid);
        sprintf(buf, "eth0.%d", vlanid);
        cfg_set_option_value(tuple, buf);
        sprintf(tuple, "network.lan%d.type", vlanid);
        cfg_set_option_value(tuple, "bridge");
        sprintf(tuple, "network.lan%d.proto", vlanid);
        cfg_set_option_value(tuple, "dhcp");
        sprintf(tuple, "network.lan%d.igmp_snooping", vlanid);
        cfg_set_option_value_int(tuple, 1);

        //network.vlan1=switch_vlan
        sprintf(buf, "vlan%d", vlanid);
        cfg_add_section_with_name_type("network", buf, "switch_vlan");
        //network.vlan1.device='switch0'
        sprintf(tuple, "network.vlan%d.device", vlanid);
        cfg_set_option_value(tuple, "switch0");
        //network.vlan1.vlan='1'
        sprintf(tuple, "network.vlan%d.vlan", vlanid);
        cfg_set_option_value_int(tuple, vlanid);
        //network.vlan1.ports='0t 1t'
        sprintf(tuple, "network.vlan%d.ports", vlanid);
        if (vlanid == 1) {
            cfg_set_option_value(tuple, "0t 1");
        } else {
            cfg_set_option_value(tuple, "0t 1t");
        }

        //set default value here
        //network.lan1.vlan_name
        sprintf(tuple, "network.lan%d.vlan_name", i);
        sprintf(buf, "VLAN %04d", i);
        cfg_set_option_value(tuple, buf);
        sprintf(tuple, "network.lan%d.vlan_description", i);
        cfg_set_option_value(tuple, buf);
    }

    return 0;
}

int vlan_destroy(int vlanid, int endid)
{
    int i;
    char tuple[128];
    for (i = vlanid; i <= endid; ++i) {
        if (i == 1) {
            continue;
        }
        //network.lan1=interface
        sprintf(tuple, "network.lan%d=interface", vlanid);
        cfg_del_section(tuple);
        //network.vlan1=switch_vlan
        sprintf(tuple, "network.vlan%d=switch_vlan", vlanid);
        cfg_del_section(tuple);
    }

    return 0;
}

int vlan_undo_name(int vlanid)
{
    char tuple[128];
    char buf[20];
    sprintf(tuple, "network.lan%d.vlan_name", vlanid);
    sprintf(buf, "VLAN %04d", vlanid);
    cfg_set_option_value(tuple, buf);

    return 0;
}

int vlan_set_name(int vlanid, const char *name)
{
    char tuple[128];
    sprintf(tuple, "network.lan%d.vlan_name", vlanid);
    cfg_set_option_value(tuple, name);
    return 0;
}

int vlan_undo_desc(int vlanid)
{
    char tuple[128];
    char buf[20];
    sprintf(tuple, "network.lan%d.vlan_description", vlanid);
    sprintf(buf, "VLAN %04d", vlanid);
    cfg_set_option_value(tuple, buf);
    return 0;
}

int vlan_set_desc(int vlanid, const char *desc)
{
    char tuple[128];
    sprintf(tuple, "network.lan%d.vlan_description", vlanid);
    cfg_set_option_value(tuple, desc);
    return 0;
}

void vlan_list_id_free(int **idlist)
{
    if (idlist == NULL || *idlist == NULL) {
        return ;
    }
    free(*idlist);
    *idlist = NULL;
}


static const char * vlan_port_type_string[] = {"access", "trunk", "hybrid"};
int vlan_set_type(const char *port_name, int type)
{
    //char tuple[128];
    //sprintf(tuple, "vlan_port.VLAN%s.type", port_name);
    //cfg_set_option_value(tuple, vlan_port_type_string[type]);
    return 0;
}

int vlan_set_pvid(const char *port_name, int pvid, int type)
{
    char tuple[128];
    char buf[128];
    if (!strncmp(port_name, "ath", 3)) {
        //wireless.ath13.network='lan'
        sprintf(tuple, "wireless.%s.network", port_name);
        sprintf(buf, "lan%d", pvid);
        cfg_set_option_value(tuple, buf);
    } else {
        sprintf(tuple, "network.lan%d.ifname", pvid);
        cfg_get_option_value(tuple, buf, sizeof(buf));
        if (!strstr(buf, "eth0.4090")) {
            strcat(buf, " ");
            strcat(buf, "eth0.4090");
            cfg_set_option_value(tuple, buf);
        }
    }

    //sprintf(tuple, "vlan_port.VLAN%s.pvid", port_name);
    //cfg_set_option_value_int(tuple, pvid);
    return 0;
}

int vlan_permit_all(const char * name)
{
    return 0;
}

int vlan_undo_permit_all(const char * name)
{
    return 0;
}

int vlan_permit(const char * name, int start, int end)
{
    return 0;
}

static int vlan_dialer_iterator_id(struct uci_package *p, void *arg)
{
    struct uci_element *e1, *e2;
    int num = 0; 
    int is_dialer = 0;
    vlan_interface_info *idlist = (vlan_interface_info *)arg;

    uci_foreach_element(&p->sections, e1) {
        struct uci_section *s = uci_to_section(e1);
        if(!sscanf(s->e.name, "lan%d", &(idlist->info[num].id))) {
            continue;
        }
        is_dialer = 0;

        uci_foreach_element(&s->options, e2) {
            struct uci_option *o = uci_to_option(e2);
            if (!strcmp(o->e.name, "proto")) {
                is_dialer = 1;
                if (!strcmp(o->v.string, "static")) {
                    idlist->info[num].type = IP_TYPE_STATIC;
                } else {
                    idlist->info[num].type = IP_TYPE_DHCP;
                    break;
                }
            } else if (!strcmp(o->e.name, "ipaddr")) {
                strcpy(idlist->info[num].address, o->v.string);
            } else if (!strcmp(o->e.name, "netmask")) {
                strcpy(idlist->info[num].netmask, o->v.string);
            }
        }

        if (is_dialer) {
            num++;
        }
    }
    idlist->count = num;

    return 0;
}


int vlan_get_dialer_info(vlan_interface_info **info)
{
    *info = malloc(sizeof(vlan_interface_info));
    if (*info == NULL) {
        return -1;
    }
    
    memset(*info, 0, sizeof(vlan_interface_info));
    return cfg_visit_package(VLAN_CFG_PACKAGE, vlan_dialer_iterator_id, *info);
}

int vlan_get_ifname(int vlanid, char *ifname)
{
    sprintf(ifname, "lan%d", vlanid);
    return 0;
}

int dialer_undo(const char *ifname, int type)
{
    char tuple[128];

    /*
     * hardcode other lan interface with dhcp
     */
    if (strcmp(ifname, "lan1"))
        return 0;

    if (type == IP_TYPE_DHCP) {
        //network.lan1.proto='dhcp'
        sprintf(tuple, "network.%s.proto", ifname);
        cfg_del_option(tuple);
    } else if (IP_TYPE_STATIC) {
        //network.lan1.proto='static'                                                 
        //network.lan1.ipaddr='127.0.0.1'                                             
        //network.lan1.netmask='255.0.0.0'                                            
        sprintf(tuple, "network.%s.proto", ifname);
        cfg_del_option(tuple);
        sprintf(tuple, "network.%s.ipaddr", ifname);
        cfg_del_option(tuple);
        sprintf(tuple, "network.%s.netmask", ifname);
        cfg_del_option(tuple);
    }
    return 0;
}

int dialer_set_dhcp(const char *ifname)
{
    char tuple[128];
    sprintf(tuple, "network.%s.proto", ifname);
    cfg_set_option_value(tuple, "dhcp");
    sprintf(tuple, "network.%s.dhcp_default_ip", ifname);
    cfg_set_option_value(tuple, DHCP_DEFAULT_IP);
    sprintf(tuple, "network.%s.dhcp_default_netmask", ifname);
    cfg_set_option_value(tuple, DHCP_DEFAULT_NETMASK);
    cfg_set_option_value("network.alias.interface", ifname);

    return 0;
}

int dialer_static_set_ipv4(const char *ifname, const char *ip,
        const char *netmask, const char *gateway)
{
    char tuple[128];
    sprintf(tuple, "network.%s.proto", ifname);
    cfg_set_option_value(tuple, "static");
    sprintf(tuple, "network.%s.ipaddr", ifname);
    cfg_set_option_value(tuple, ip);
    sprintf(tuple, "network.%s.netmask", ifname);
    cfg_set_option_value(tuple, netmask);
    sprintf(tuple, "network.%s.gateway", ifname);
    cfg_set_option_value(tuple, gateway);
    return 0;
}
