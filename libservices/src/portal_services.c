#include <uci.h>
#include <stdlib.h>
#include <string.h>

#include "services/util_services.h"
#include "services/cfg_services.h"
#include "services/portal_services.h"

int portal_scheme_create(char *name)
{
    //portal.aa
    cfg_add_section(PORTAL_SCHEME_CFG_PACKAGE, name);

    //portal.aa.enabled
    char tuple[128];
    sprintf(tuple, "portal.%s.enabled", name);
    cfg_set_option_value(tuple, "disabled");
    return 0;
}

int portal_scheme_destroy(char *name)
{
    //portal.aa
    char tuple[128];
    sprintf(tuple, "portal.%s", name);
    cfg_del_option(tuple);
    return 0;
}

int portal_scheme_enable(char * name)
{
    //portal.aa.enabled
    char tuple[128];
    sprintf(tuple, "portal.%s.enabled", name);
    cfg_set_option_value(tuple, "enabled");
    return 0;
}

int portal_scheme_disable(char * name)
{
    //portal.aa.enabled
    char tuple[128];
    sprintf(tuple, "portal.%s.enabled", name);
    cfg_set_option_value(tuple, "disabled");
    return 0;
}

int portal_scheme_add_ipacl(char * name, char *ip, unsigned int cidr)
{
    //portal.aa.iplist
    char iplist[40];
    char tuple[128];
    snprintf(iplist, sizeof(iplist), "%s/%u", ip, cidr);
    sprintf(tuple, "portal.%s.iplist", name);
    cfg_add_option_list_value(tuple, iplist);
    return 0;
}

int portal_scheme_del_ipacl(char * name, char *ip, unsigned int cidr)
{
    return 0; 
}

int portal_scheme_flush_ipacl(char * name)
{
    //portal.bb.iplist='192.168.0.0/24'
    char tuple[128];
    sprintf(tuple, "portal.%s.iplist", name);
    cfg_del_section(tuple);
    return 0;
}


int portal_scheme_uri(char *name, char *uri)
{
    //portal.aa.url
    char tuple[128];
    sprintf(tuple, "portal.%s.url", name);
    cfg_set_option_value(tuple, uri);
    return 0;
}

int portal_scheme_blackip(char *name, char *authip, char *wechatip)
{
    char tuple[128];
    //portal.aa.wechatip='192.168.1.1'
    if (wechatip) {
        sprintf(tuple, "portal.%s.wechatip", name);
        cfg_set_option_value(tuple, wechatip);
    }

    //portal.aa.authip='192.168.1.1'
    sprintf(tuple, "portal.%s.authip", name);
    cfg_set_option_value(tuple, authip);
    return 0;
}

int portal_scheme_set_dnsset(char * portal_scheme, char *set_name)
{
    //portal.aa.dns_set='name'
    char tuple[128];
    sprintf(tuple, "portal.%s.dns_set", portal_scheme);
    cfg_set_option_value(tuple, set_name);
    return 0;
}

int portal_scheme_undo_dnsset(char *portal_scheme)
{
    //portal.aa.dns_set='name'
    char tuple[128];
    sprintf(tuple, "portal.%s.dns_set", portal_scheme);
    cfg_del_option(tuple);
    return 0;
}

int wlan_set_portal_scheme(int service_template, char *portal_scheme)
{
    //wlan_service_template.ServiceTemplate1.portal_scheme='bb'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.portal_scheme", service_template);
    cfg_set_option_value(tuple, portal_scheme);
    return 0;
}

int wlan_undo_portal_scheme(int service_template)
{
    //wlan_service_template.ServiceTemplate1.portal_scheme='bb'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.portal_scheme", service_template);
    /* delete it in wlan_service_template */
    cfg_del_option(tuple);

    return 0;
}

int portal_scheme_decompile_iterator(struct uci_package * p, void * arg)
{
    return 0;
}

int portal_decompile( int fd )
{
    return 0;
}

static int portal_scheme_iterator(struct uci_package *p, void *arg)
{
    struct uci_element *e, *e1, *e2;
    struct uci_section *s;
    struct uci_option * o;
    struct portal_schemes schemes;
    char *ptr = NULL;
    int count = 0, cidr, size = 0;


    uci_foreach_element(&p->sections, e) {
        size ++;
    }
    
    if (size == 0) {
        return 0;
    }
    else if (size > PORTAL_SCHEME_MAX_SIZE) {
        size = PORTAL_SCHEME_MAX_SIZE;
    }
    schemes.config = (struct portal_scheme_cfg *)malloc(size * sizeof(struct portal_scheme_cfg));
    if (schemes.config == NULL) {
        return -1;
    }
    memset(schemes.config, 0, size * sizeof(struct portal_scheme_cfg));
    
    uci_foreach_element(&p->sections, e) {
        if (count >= size) {
            break;
        }
        s = uci_to_section(e);
        strncpy(schemes.config[count].scheme_name, s->e.name, 
            sizeof(schemes.config[count].scheme_name) - 1);
        
        uci_foreach_element(&s->options, e1) {
            o = uci_to_option(e1);
            if (strcmp(o->e.name, "enabled") == 0) {
                if (strcmp(o->v.string, "enabled") == 0) {
                    schemes.config[count].enable = 1;
                }
                else {
                    schemes.config[count].enable = 0;
                }
            }
            else if (strcmp(o->e.name, "url") == 0) {
                strncpy(schemes.config[count].uri_path, o->v.string, 
                    sizeof(schemes.config[count].uri_path) - 1);
            }
            else if (strcmp(o->e.name, "authip") == 0) {
                util_str2ip(o->v.string, &(schemes.config[count].auth_ip));
            }
            else if (strcmp(o->e.name, "wechatip") == 0) {
                util_str2ip(o->v.string, &(schemes.config[count].wechat_ip));
            }
            else if (strcmp(o->e.name, "dns_set") == 0) {
                strncpy(schemes.config[count].dns_set, o->v.string, 
                    sizeof(schemes.config[count].dns_set) - 1);
            }
            if (strcmp(o->e.name, "iplist") == 0 
                && o->type == UCI_TYPE_LIST) {
                int ip_num = 0, ip_size = (sizeof(schemes.config[count].ip_list)/sizeof(schemes.config[count].ip_list[0]));
                uci_foreach_element(&o->v.list, e2) {
                    if (ip_num >= ip_size) {
                        break;
                    }
                    ptr = strchr(e2->name, '/');
                    if(ptr)
                        *ptr++ = '\0';

                    if (ptr)
                        cidr = atoi(ptr);
                    else 
                        cidr = 32;

                    util_str2ip(e2->name, &(schemes.config[count].ip_list[ip_num].ip));
                    schemes.config[count].ip_list[ip_num].masklen = cidr;
                    ip_num ++;
    			}
                schemes.config[count].ip_num = ip_num;
            }
            
        }
        count ++;
    }

    *((struct portal_scheme_cfg **)arg) = schemes.config;
    return count;
}


int portal_scheme_get_all(struct portal_schemes *schemes)
{
    int num;
    
    num = cfg_visit_package(PORTAL_SCHEME_CFG_PACKAGE, portal_scheme_iterator, &(schemes->config));
    if (num < 0) {
        return -1;
    }

    schemes->num = num;
    return 0;
}

void portal_scheme_free_all(struct portal_schemes *schemes)
{
    if (schemes && schemes->config) {
        free (schemes->config);
    }
}

static int portal_check_iterator(struct uci_package * p, void * arg)
{
    return 1;
}

/*return 0 if exist , 1 (none)  if not */
static int if_portal_scheme_exist(char * name)
{

    return 0;
}

static void dumpif_name_by_index(int fd, int ifindex)
{
	return;
}
int dump_portal_scheme_basic(int writefd, char *scheme_name) 
{
	return 0;
}

int dump_portal_scheme_ipacl(int writefd, char *scheme_name) 
{
	return 0;
}

int dump_portal_scheme_sta(int writefd, char *scheme_name) 
{
	return 0;
}

int portal_scheme_del_sta(char * scheme_name, char * clientmac) 
{
	return 0;
}

int portald_scheme_update_domain(char * domain_name)
{
    //system.domain.domain='aa'
    if (!domain_name) {
        cfg_del_section("system.domain");
    } else {
        cfg_add_section("system","domain");
        cfg_set_option_value("system.domain.domain", domain_name);
    }
    return 0;
}

int portal_scheme_authentication(char * scheme_name, char * clientmac, unsigned int time) 
{
	return 0;
}

int portal_preauth_ctrl(int ctrl)
{
    return 0;
} 

int portal_preauth_enable(void) {
    return portal_preauth_ctrl(1);
}

int portal_preauth_disable(void) {
    return portal_preauth_ctrl(0);
}


