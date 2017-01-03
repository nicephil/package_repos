#ifndef __VLAN_SERVICES_H_
#define __VLAN_SERVICES_H_

extern int vlan_list_id(int **idlist);
extern int vlan_create(int vlanid, int endid);
extern int vlan_destroy(int vlanid, int endid);
extern int vlan_undo_name(int vlanid);
extern int vlan_set_name(int vlanid, const char *name);
extern int vlan_undo_desc(int vlanid);
extern int vlan_set_desc(int vlanid, const char *desc);
extern void vlan_list_id_free(int **idlist);

#endif /* __VLAN_SERVICES_H_ */
