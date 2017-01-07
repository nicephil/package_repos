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
        sscanf(s->e.name, "VLAN%d", &id);
        if (id > 0) {
            idlist[num++] = id;
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
        sprintf(buf, "%s.VLAN%d", i);
        cfg_add_section(VLAN_CFG_PACKAGE, buf);

        // set default value here
        sprintf(tuple, "vlan.VLAN%d.name", i);
        sprintf(buf, "VLAN %04d", i);
        cfg_set_option_value(tuple, buf);
        sprintf(tuple, "vlan.VLAN%d.description", i);
        cfg_set_option_value(tuple, buf);
    }

    return 0;
}

int vlan_destroy(int vlanid, int endid)
{
    int i;
    char buf[20];
    for (i = vlanid; i <= endid; ++i) {
        if (i == 1) {
            continue;
        }
        sprintf(buf, "vlan.VLAN%d", i);
        cfg_del_section(buf);

    }

    return 0;
}

int vlan_undo_name(int vlanid)
{
    char tuple[128];
    char buf[20];
    sprintf(tuple, "vlan.VLAN%d.name", vlanid);
    sprintf(buf, "VLAN %04d", vlanid);
    cfg_set_option_value(tuple, buf);

    return 0;
}

int vlan_set_name(int vlanid, const char *name)
{
    char tuple[128];
    sprintf(tuple, "vlan.VLAN%d.name", vlanid);
    cfg_set_option_value(tuple, name);
    return 0;
}

int vlan_undo_desc(int vlanid)
{
    char tuple[128];
    char buf[20];
    sprintf(tuple, "vlan.VLAN%d.description", vlanid);
    sprintf(buf, "VLAN %04d", vlanid);
    cfg_set_option_value(tuple, buf);
    return 0;
}

int vlan_set_desc(int vlanid, const char *desc)
{
    char tuple[128];
    sprintf(tuple, "vlan.VLAN%d.description", vlanid);
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
    char tuple[128];
    sprintf(tuple, "vlan_port.VLAN%s.type", port_name);
    cfg_set_value(tuple, vlan_port_type_string[type]);
    return 0;
}

int vlan_set_pvid(const char * port_name, int pvid, int type)
{
    char tuple[128];
    sprintf(tuple, "vlan_port.VLAN%s.pvid", port_name);
    cfg_set_value_int(tuple, pvid);
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
