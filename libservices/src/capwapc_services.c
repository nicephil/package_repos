#include <uci.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>


#include "services/capwapc_services.h"

static int g_init = 0;

extern struct capwapc_config g_capwapc_config;

int capwapc_cfg_server_init(struct capwapc_config *cfg)
{
    if (g_init) {
        return 0;
    }
    struct uci_context *ctx;
    struct uci_package *p;
    struct uci_element *e1;
    struct uci_element *e2;

    ctx = uci_alloc_context();
    uci_load(ctx, CAPWAPC_CFG_PACKAGE, &p);

    uci_foreach_element(&p->sections, e1) {
        struct uci_section *s_cur = uci_to_section(e1);
        if (!strcmp(s_cur->e.name, CAPWAPC_CFG_SECTION_SERVER)) {
            uci_foreach_element(&s_cur->options, e2) {
                struct  uci_option *o_cur = uci_to_option(e2);
                if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_MASSER)) {
                    strncpy(cfg->mas_server, o_cur->v.string, sizeof(cfg->mas_server));
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_SLASER)) {
                    strncpy(cfg->sla_server, o_cur->v.string, sizeof(cfg->sla_server));
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_DEFSER)) {
                    strncpy(cfg->def_server, o_cur->v.string, sizeof(cfg->def_server));
                }
            }
        }
    }

    uci_unload(ctx, p);
    uci_free_context(ctx);
    g_init = 1;
    return 0;
}

int capwapc_get_server_pri(char *server, int *server_pri)
{
    struct capwapc_config *config = &g_capwapc_config;
    int pri = 0, rel_pri = 0;

    capwapc_cfg_server_init(config);

    /* step1: check if it's the static master server */
    if(config->mas_server[0] != 0){
        if(!strcmp(server, config->mas_server)){
            SET_STANDBY_PRI(pri, MASTER_ADDRESS);
            SET_ABSOLUTE_PRI(pri, STATIC_NMS);
            SET_RELATIVE_PRI(pri, rel_pri);
            syslog(LOG_DEBUG, "Server %s is the static master server with priority %d.\n", 
                server, pri);
            *server_pri = pri;
            return 0;
        }
        rel_pri++;
    }

    /* step2: check if it's the static slave server */
    if(config->sla_server[0] != 0){       
        if(!strcmp(server, config->sla_server)){
            SET_STANDBY_PRI(pri, SLAVE_ADDRESS);
            SET_ABSOLUTE_PRI(pri, STATIC_NMS);
            SET_RELATIVE_PRI(pri, rel_pri);
            syslog(LOG_DEBUG, "Server %s is the static slave server with priority %d.\n", 
                server, pri);
            *server_pri = pri;
            return 0;
        }
        rel_pri++;
    }

    /* step3: check if it's the dhcp43 master server */

    /* step4: check if it's the dhcp43 slave server */

    /* step5: check if it's the static default server */
    if(config->def_server[0] != 0){
        if(!strcmp(server, config->def_server)){
            rel_pri = 0xFF;   /* default server is of the lowest priority */
            SET_ABSOLUTE_PRI(pri, DEFAULT_NMS);
            SET_RELATIVE_PRI(pri, rel_pri);
            syslog(LOG_DEBUG, "Server %s is the default server with priority %d.\n", 
                server, pri);
            *server_pri = pri;
            return 0;
        }
    } 

    /* step6: others we think it was discoveried by broadcast */
    SET_ABSOLUTE_PRI(pri, BORADCAST_NMS);
    SET_RELATIVE_PRI(pri, rel_pri);

    *server_pri = pri;

    syslog(LOG_DEBUG, "Server %s was discoveried by broadcast with priority %d.\n", 
        server, pri);
    
    return 0;
}

