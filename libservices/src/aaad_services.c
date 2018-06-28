#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "services/aaad_services.h"
#include "services/util_services.h"
#include "services/cfg_services.h"

int radius_scheme_create(const char * name)
{
    //radius_scheme.aa
    cfg_add_section(CFG_RADIUS_SCHEME_PACKAGE, name);
    return 0;
}

int radius_scheme_set_pri_auth(const char * name, 
        const char *addr, unsigned int port, 
        int key_crypt, const char * key)
{
    char tuple[256];
    //radius_scheme.aa.primary_authentication_ip="1.1.1.1"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_PRI_AUTH_IP);
    cfg_set_option_value(tuple, addr);
    //radius_scheme.aa.primary_authentication_port="1812"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_PRI_AUTH_PORT);
    cfg_set_option_value_int(tuple, port);
    //radius_scheme.aa.primary_authentication_key_crypt="plain"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_PRI_AUTH_KEY_CRYPT);
    cfg_set_option_value(tuple, "plain");
    //radius_scheme.aa.primary_authentication_key="123456"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_PRI_AUTH_KEY);
    cfg_set_option_value(tuple, key);
    return 0;
}

int radius_scheme_set_pri_acct(const char * name, 
        const char *addr, unsigned int port, 
        int key_crypt, const char * key)
{
    char tuple[256];
    //radius_scheme.aa.primary_accounting_ip="1.1.1.1"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_PRI_ACCT_IP);
    cfg_set_option_value(tuple, addr);
    //radius_scheme.aa.primary_accounting_port="1812"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_PRI_ACCT_PORT);
    cfg_set_option_value_int(tuple, port);
    //radius_scheme.aa.primary_accounting_key_crypt="plain"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_PRI_ACCT_KEY_CRYPT);
    cfg_set_option_value(tuple, "plain");
    //radius_scheme.aa.primary_accounting_key="123456"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_PRI_ACCT_KEY);
    cfg_set_option_value(tuple, key);
    return 0;
}

int radius_scheme_set_sec_auth(const char * name, 
        const char *addr, unsigned int port, 
        int key_crypt, const char * key)
{
    char tuple[256];
    //radius_scheme.aa.secondary_authentication_ip="1.1.1.1"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_SEC_AUTH_IP);
    cfg_set_option_value(tuple, addr);
    //radius_scheme.aa.secondary_authentication_port="1812"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_SEC_AUTH_PORT);
    cfg_set_option_value_int(tuple, port);
    //radius_scheme.aa.secondary_authentication_key_crypt="plain"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_SEC_AUTH_KEY_CRYPT);
    cfg_set_option_value(tuple, "plain");
    //radius_scheme.aa.secondary_authentication_key="123456"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_SEC_AUTH_KEY);
    cfg_set_option_value(tuple, key);
    return 0;
}

int radius_scheme_set_sec_acct(const char * name, 
        const char *addr, unsigned int port, 
        int key_crypt, const char * key)
{
    char tuple[256];
    //radius_scheme.aa.priondary_accounting_ip="1.1.1.1"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_SEC_ACCT_IP);
    cfg_set_option_value(tuple, addr);
    //radius_scheme.aa.priondary_accounting_port="1812"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_SEC_ACCT_PORT);
    cfg_set_option_value_int(tuple, port);
    //radius_scheme.aa.priondary_accounting_key_crypt="plain"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_SEC_ACCT_KEY_CRYPT);
    cfg_set_option_value(tuple, "plain");
    //radius_scheme.aa.priondary_accounting_key="123456"
    sprintf(tuple, "%s.%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name, CFG_RADIUS_SEC_ACCT_KEY);
    cfg_set_option_value(tuple, key);
    return 0;
}

int radius_scheme_delete_force(const char * name)
{
    //radius_scheme.aa
    char tuple[256];
    sprintf(tuple, "%s.%s", CFG_RADIUS_SCHEME_PACKAGE, name);
    cfg_del_option(tuple);
    return 0;
}

static int radius_scheme_list_json(struct uci_package * p, void * arg)
{
    struct uci_element *e1, *e2;
    struct uci_section *s;
    struct uci_option *o;
    int num= 0;
    
    struct radius_scheme_json *radiusinfo = (struct radius_scheme_json *)arg;

    uci_foreach_element(&p->sections, e1) {
        s = uci_to_section(e1);
        strncpy(radiusinfo->config[num].name, s->e.name, sizeof(radiusinfo->config[num].name) - 1);
        uci_foreach_element(&s->options, e2) {
            o = uci_to_option(e2);
            if (o->type == UCI_TYPE_STRING) {
                if (!strcmp(o->e.name, CFG_RADIUS_PRI_AUTH_IP)){
                    strncpy(radiusinfo->config[num].primary_auth_ip, o->v.string, 
                        sizeof(radiusinfo->config[num].primary_auth_ip));
                }
                else if (!strcmp(o->e.name, CFG_RADIUS_PRI_AUTH_PORT)){
                    radiusinfo->config[num].primary_auth_port = atoi(o->v.string);
                }
                else if(!strcmp(o->e.name, CFG_RADIUS_PRI_AUTH_KEY)){
                    strncpy(radiusinfo->config[num].primary_auth_key, o->v.string, sizeof(radiusinfo->config[num].primary_auth_key) - 1);
                }
                else if(!strcmp(o->e.name, CFG_RADIUS_PRI_AUTH_KEY_CRYPT)){
                    if (!strcmp(o->v.string, "cipher"))
                        radiusinfo->config[num].primary_auth_key_crypt = RADIUS_KEY_CRYPT_CIPHER;
                    else if(!strcmp(o->v.string, "plain"))
                        radiusinfo->config[num].primary_auth_key_crypt = RADIUS_KEY_CRYPT_PLAIN;
                }
                else if (!strcmp(o->e.name, CFG_RADIUS_PRI_ACCT_IP)){
                    strncpy(radiusinfo->config[num].primary_acct_ip, o->v.string, 
                        sizeof(radiusinfo->config[num].primary_acct_ip));
                }
                else if (!strcmp(o->e.name, CFG_RADIUS_PRI_ACCT_PORT)){
                    radiusinfo->config[num].primary_acct_port= atoi(o->v.string);
                }
                else if(!strcmp(o->e.name, CFG_RADIUS_PRI_ACCT_KEY)){
                    strncpy(radiusinfo->config[num].primary_acct_key, o->v.string, sizeof(radiusinfo->config[num].primary_acct_key) - 1);
                }
                else if(!strcmp(o->e.name, CFG_RADIUS_PRI_ACCT_KEY_CRYPT)){
                    if (!strcmp(o->v.string, "cipher"))
                        radiusinfo->config[num].primary_acct_key_crypt = RADIUS_KEY_CRYPT_CIPHER;
                    else if(!strcmp(o->v.string, "plain"))
                        radiusinfo->config[num].primary_acct_key_crypt = RADIUS_KEY_CRYPT_PLAIN;
                }
                else if (!strcmp(o->e.name, CFG_RADIUS_SEC_AUTH_IP)){
                    strncpy(radiusinfo->config[num].secondary_auth_ip, o->v.string, 
                        sizeof(radiusinfo->config[num].secondary_auth_ip));
                }
                else if (!strcmp(o->e.name, CFG_RADIUS_SEC_AUTH_PORT)){
                    radiusinfo->config[num].secondary_auth_port= atoi(o->v.string);
                }
                else if(!strcmp(o->e.name, CFG_RADIUS_SEC_AUTH_KEY)){
                    strncpy(radiusinfo->config[num].secondary_auth_key, o->v.string, sizeof(radiusinfo->config[num].secondary_auth_key) - 1);
                }
                else if(!strcmp(o->e.name, CFG_RADIUS_SEC_AUTH_KEY_CRYPT)){
                    if (!strcmp(o->v.string, "cipher"))
                        radiusinfo->config[num].secondary_auth_key_crypt= RADIUS_KEY_CRYPT_CIPHER;
                    else if(!strcmp(o->v.string, "plain"))
                        radiusinfo->config[num].secondary_auth_key_crypt= RADIUS_KEY_CRYPT_PLAIN;
                }
                else if (!strcmp(o->e.name, CFG_RADIUS_SEC_ACCT_IP)){
                    strncpy(radiusinfo->config[num].secondary_acct_ip, o->v.string, 
                        sizeof(radiusinfo->config[num].secondary_acct_ip));
                }
                else if (!strcmp(o->e.name, CFG_RADIUS_SEC_ACCT_PORT)){
                    radiusinfo->config[num].secondary_acct_port= atoi(o->v.string);
                }
                else if(!strcmp(o->e.name, CFG_RADIUS_SEC_ACCT_KEY)){
                    strncpy(radiusinfo->config[num].secondary_acct_key, o->v.string, sizeof(radiusinfo->config[num].secondary_acct_key) - 1);
                }
                else if(!strcmp(o->e.name, CFG_RADIUS_SEC_ACCT_KEY_CRYPT)){
                    if (!strcmp(o->v.string, "cipher"))
                        radiusinfo->config[num].secondary_acct_key_crypt= RADIUS_KEY_CRYPT_CIPHER;
                    else if(!strcmp(o->v.string, "plain"))
                        radiusinfo->config[num].secondary_acct_key_crypt= RADIUS_KEY_CRYPT_PLAIN;
                }
            }
        }
        num++;
    }
    radiusinfo->num = num;

    return 0;
}

int radius_scheme_get_all(struct radius_scheme_json *schemes)
{
    return cfg_visit_package(CFG_RADIUS_SCHEME_PACKAGE, radius_scheme_list_json, schemes);
}

