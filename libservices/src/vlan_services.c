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
        if (!strncmp(s->e.name, VLAN_BR_PREFIX, 6)) {
            sscanf(s->e.name, VLAN_BR_PREFIX"%d", &id);
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
        sprintf(buf, "network.lan%d", vlanid);
        cfg_add_section_with_name_type("network", buf, "interface");
        sprintf(tuple, "network.lan%d.ifname", vlanid);
        sprintf(buf, "eth0.%d", vlanid);
        cfg_set_option_value(tuple, buf);
        sprintf(tuple, "network.lan%d.type");
        cfg_set_option_value(tuple, "bridge");
        //network.vlan1=switch_vlan
        sprintf(buf, "vlan%d", vlanid);
        cfg_add_section_with_name_type("network", buf, "switch_vlan");
        //network.vlan1.device='switch0'
        sprintf(tuple, "network.vlan%d.device", vlanid);
        cfg_set_option_value(tuple, "switch0");
        //network.vlan1.vlan='1'
        sprintf(tuple, "network.vlan%d.vlan", vlanid);
        cfg_set_option_value_int(tuple, vlanid);
        //network.vlan1.ports='0t 1'
        sprintf(tuple, "network.vlan%d.ports", vlanid);
        cfg_set_option_value(tuple, "0t 1");

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
    char buf[33];
    //wireless.ath13.network='lan'
    sprintf(tuple, "wireless.%s.network", port_name);
    sprintf(buf, "lan%d", pvid);
    cfg_set_option_value(tuple, buf);

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
