#ifndef __VLAN_SERVICES_H_
#define __VLAN_SERVICES_H_

#define VLAN_MAX_COUNT 32
#define VLAN_CFG_PACKAGE "vlan"
#define VLAN_PORT_CFG_PACKAGE "vlan_port"

enum VLAN_PORT_TYPE {
    VLAN_PORT_TYPE_ACCESS = 0,
    VLAN_PORT_TYPE_TRUNK,
    VLAN_PORT_TYPE_HYBRID,

    VLAN_PORT_TYPE_MAX
};



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

#endif /* __VLAN_SERVICES_H_ */
