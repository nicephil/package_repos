#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "services/cfg_services.h"
#include "services/dnsset_services.h"

struct get_cfg {
    int count;
    char name[64];
    DNSSET_S *p;
};

static int dnsset_iterator_section(struct uci_section *s, void *arg)
{
    struct uci_element * e;
    DNSSET_S *set = NULL;
    KEY_S *k = NULL;
    struct get_cfg *cfg = (struct get_cfg *)arg;
    int dnsset_maxc = DNSSET_MAX_COUNT;
    int dnskey_maxc = DNSKEY_MAX_COUNT;
    
    if (cfg->name[0] != '\0' && strcmp(cfg->name, s->e.name)) {
        return -1;
    }
    
    if (cfg->count >= dnsset_maxc) {
        syslog(LOG_ERR, "Bad config. Reach max dns-set count.\n");
        return 0;
    }

    set = (DNSSET_S *)malloc(sizeof(DNSSET_S));
    if( set == NULL ) {
        syslog(LOG_ERR, "malloc dnsset failed\n");
        return -1;
    }

    memset(set, 0, sizeof(DNSSET_S));
    strcpy(set->name, s->e.name);
    uci_foreach_element(&s->options, e) {
        struct uci_option * o = uci_to_option(e);
        if ((o->type != UCI_TYPE_LIST)) {
            if (strcmp(o->e.name, "enabled") == 0) {
                if (strcmp(o->v.string, "enabled") == 0)
                    set->enable = 1;
            }
        }
        else if ((strcmp(o->e.name, "key") == 0)) {
            struct uci_element *e2;
            char  value[64];
            int  ikid;
            unsigned char kid;
            uci_foreach_element(&o->v.list, e2) {
                if (set->keycount >= dnskey_maxc) {
                    syslog(LOG_ERR, "malloc periodic time_range failed, current count(%d)\n", set->keycount);
                    break;
                }
                
                memset(value, 0, sizeof(value));
                sscanf(e2->name, "%[^/]/%d", value, &ikid);
                kid = ikid;
                if (kid < 0){
                    syslog(LOG_ERR, "Bad keyid found in config, skip it.\n");
                    continue;
                }
                
                k = (KEY_S *)malloc(sizeof(KEY_S));
                if (k == NULL) {
                    syslog(LOG_ERR, "malloc dnskey failed\n");
                    break;
                }
                strcpy(k->key, value);
                k->kid = kid;
                
                k->next = set->keylist;
                set->keylist = k;
                set->keycount++;
            }
        }
    }

    set->next = cfg->p;
    cfg->p = set;
    cfg->count++;
    
    return 0;
}

static int dns_set_iterator(struct uci_package *p, void *arg)
{
    struct uci_element *e;

    uci_foreach_element(&p->sections, e) {
        struct uci_section *s = uci_to_section(e);
        dnsset_iterator_section(s, arg);
    }
    return 0;
}

DNSSET_S *dnsset_cfg_getall(void)
{
    struct get_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg_visit_package(DNSSET_CFG_PACKAGE, dns_set_iterator, &cfg);

    return (DNSSET_S *)cfg.p;
}

int dnsset_destroy(char *name)
{
    //dns_set.aa
    char tuple[128];
    sprintf(tuple,"dns_set.%s", name);
    cfg_del_option(tuple);
    return 0;
}

void dnsset_cfg_free(DNSSET_S *dns_set)
{
    DNSSET_S *p, *pb = dns_set;
    KEY_S *k, *kb;

    while ((p = pb)){
        pb = p->next;
        kb = p->keylist;
        while((k=kb)){
            kb=kb->next;
            free(k);
        }
        free(p);
    }
    
    return ;
}


int dnsset_create(char * name)
{

    cfg_add_section(DNSSET_CFG_PACKAGE, name);
    //dns_set.aa.enabled='enabled'
    char tuple[128];
    sprintf(tuple, "dns_set.%s.enabled", name);
    cfg_set_option_value(tuple, "disabled");
    return 0;
}

int dnsset_disable(char *name)
{
    //dns_set.aa.enabled='enabled'
    char tuple[128];
    sprintf(tuple, "dns_set.%s.enabled", name);
    cfg_set_option_value(tuple, "disabled");
}

int dnsset_add_key(char * name, char *key)
{
    //dns_set.aa.key='19214/24' '2444/2'
    char tuple[128];
    sprintf(tuple, "dns_set.%s.key", name);
    cfg_add_option_list_value(tuple, key);
    return 0;
}

int dnsset_enable(char *name)
{
    //dns_set.aa.enabled='enabled'
    char tuple[128];
    sprintf(tuple, "dns_set.%s.enabled", name);
    cfg_set_option_value(tuple, "enabled");
    return 0;
}
