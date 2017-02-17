#include <uci.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>


#include "services/capwapc_services.h"

int capwapc_get_curcfg(struct capwapc_config *cfg)
{
    struct uci_context *ctx;
    struct uci_package *p;
    struct uci_element *e1;
    struct uci_element *e2;

    ctx = uci_alloc_context();
    uci_load(ctx, CAPWAPC_CFG_PACKAGE, &p);

    uci_foreach_element(&p->sections, e1) {
        struct uci_section *s_cur = uci_to_section(e1);
        if (!strcmp(s_cur->e.name, CAPWAPC_CFG_SECTION_GLOBAL)) {
            uci_foreach_element(&s_cur->options, e2) {
                struct  uci_option *o_cur = uci_to_option(e2);
                /* capwapc.global.enable='1' */
                if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_ENABLE)) {
                    cfg->enable = atoi(o_cur->v.string);
                }
            }
        } else if (!strcmp(s_cur->e.name, CAPWAPC_CFG_SECTION_SERVER)) {
            uci_foreach_element(&s_cur->options, e2) {
                struct  uci_option *o_cur = uci_to_option(e2);
                /* capwapc.server.mas_server='139.196.188.253' */
                if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_MASSER)) {
                    strncpy(cfg->mas_server, o_cur->v.string, sizeof(cfg->mas_server));
                    /* capwapc.server.sla_server='139.196.188.253' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_SLASER)) {
                    strncpy(cfg->sla_server, o_cur->v.string, sizeof(cfg->sla_server));
                    /* capwapc.server.def_server='redirector.oakridge.io' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_DEFSER)) {
                    strncpy(cfg->def_server, o_cur->v.string, sizeof(cfg->def_server));
                    /* capwapc.server.opt43_mas_server='139.196.188.253' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_OPT43_MASSER)) {
                    strncpy(cfg->mas_server, o_cur->v.string, sizeof(cfg->opt43_mas_server));
                    /* capwapc.server.opt43_sla_server='139.196.188.253' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_OPT43_SLASER)) {
                    strncpy(cfg->sla_server, o_cur->v.string, sizeof(cfg->opt43_sla_server));
                }
            }
        } else if (!strcmp(s_cur->e.name, CAPWAPC_CFG_SECTION_WTP)) {
            uci_foreach_element(&s_cur->options, e2) {
                struct  uci_option *o_cur = uci_to_option(e2);
                /* capwapc.wtp.ctrl_port='5246' */
                if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_CTRLPORT)) {
                    cfg->ctrl_port = atoi(o_cur->v.string);
                    /* capwapc.wtp.mtu='1300' */ 
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_MTU)) {
                    cfg->mtu = atoi(o_cur->v.string);
                    /* capwapc.wtp.disc_intv='20' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_DISCINTV)) {
                    cfg->disc_intv = atoi(o_cur->v.string);
                    /* capwapc.wtp.maxdisc_intv='5' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_MAXDISCINTV)) {
                    cfg->maxdisc_intv = atoi(o_cur->v.string);
                    /* capwapc.wtp.echo_intv='30' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_ECHOINTV)) {
                    cfg->echo_intv = atoi(o_cur->v.string);
                    /* capwapc.wtp.retran_intv='3' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_RETRANINTV)) {
                    cfg->retran_intv = atoi(o_cur->v.string);
                    /* capwapc.wtp.silent_intv='30' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_SILENTINTV)) {
                    cfg->silent_intv = atoi(o_cur->v.string);
                    /* capwapc.wtp.join_timeout='60' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_SILENTINTV)) {
                    cfg->join_timeout = atoi(o_cur->v.string);
                    /* capwapc.wtp.max_disces='10' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_MAXDISCES)) {
                    cfg->max_disces = atoi(o_cur->v.string);
                    /* capwapc.wtp.max_retran='5' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_MAXRETRANS)) {
                    cfg->max_retran = atoi(o_cur->v.string);
                    /* capwapc.wtp.location='aa' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_LOCATION)) {
                    strcpy(cfg->location, o_cur->v.string);
                    /* capwapc.wtp.domain ='aa' */
                } else if (!strcmp(o_cur->e.name, CAPWAPC_CFG_OPTION_DOMAIN)) {
                    strcpy(cfg->domain, o_cur->v.string);
                }
            }
        }
    }

    uci_unload(ctx, p);
    uci_free_context(ctx);
    return 0;
}

int capwapc_get_server_pri(struct capwapc_config *config, char *server, int *server_pri)
{
    int pri = 0, rel_pri = 0;

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
    if (config->opt43_mas_server[0] != 0) {
        if(!strcmp(server, config->opt43_mas_server)){
            SET_STANDBY_PRI(pri, MASTER_ADDRESS);
            SET_ABSOLUTE_PRI(pri, DHCP_NMS);
            SET_RELATIVE_PRI(pri, rel_pri);
            syslog(LOG_DEBUG, "Server %s is the dhcp43 master server with priority %d.\n", 
                server, pri);
            return pri;
        }
        rel_pri++;
    }

    /* step4: check if it's the dhcp43 slave server */
    if (config->opt43_sla_server[0] != 0) {
        if(!strcmp(server, config->opt43_sla_server)){
            SET_STANDBY_PRI(pri, SLAVE_ADDRESS);
            SET_ABSOLUTE_PRI(pri, DHCP_NMS);
            SET_RELATIVE_PRI(pri, rel_pri);
            syslog(LOG_DEBUG, "Server %s is the dhcp43 slave server with priority %d.\n", 
                server, pri);
            return pri;
        }
        rel_pri++;
    }


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

int capwapc_set_location(const char *location)
{
    cfg_set_option_value(CAPWAPC_CFG_OPTION_LOCATION_TUPLE, location);

    return 0;
}

int capwapc_undo_location(void)
{

    cfg_del_option(CAPWAPC_CFG_OPTION_LOCATION_TUPLE);

    return 0;
}


int capwapc_set_domain(const char *domain)
{
#if !OK_PATCH
    cfg_set_option_value(CAPWAPC_CFG_OPTION_DOMAIN_TUPLE);
#endif

    return 0;
}

int capwapc_undo_domain(void)
{
#if !OK_PATCH
    cfg_del_option(CAPWAPC_CFG_OPTION_DOMAIN_TUPLE);
#endif

    return 0;
}

int capwapc_get_defcfg(capwapc_config *defcfg)
{
    defcfg->enable = CAPWAPC_DEFAULT_ENABLE;
    defcfg->location[0] = '\0';
    defcfg->domain[0] = '\0';
    defcfg->mas_server[0] = '\0';
    defcfg->sla_server[0] = '\0';
    strcpy(defcfg->def_server, CAPWAPC_DEFAULT_SERVER);
    defcfg->ctrl_port =  CAPWAPC_DEFAULT_CTRLPORT;
    defcfg->mtu = CAPWAPC_DEFAULT_MTU;
    defcfg->disc_intv = CAPWAPC_DEFAULT_DISCINTV;
    defcfg->maxdisc_intv = CAPWAPC_DEFAULT_MAXDISCINTV;
    defcfg->echo_intv = CAPWAPC_DEFAULT_ECHOINTV;
    defcfg->retran_intv = CAPWAPC_DEFAULT_RETRANINTV;
    defcfg->silent_intv = CAPWAPC_DEFAULT_SILENTINTV;
    defcfg->join_timeout = CAPWAPC_DEFAULT_JIONTIMEOUT;
    defcfg->max_disces = CAPWAPC_DEFAULT_MAXDISCES ;
    defcfg->max_retran = CAPWAPC_DEFAULT_MAXRETRAN;

    return 0;
}


int capwapc_set_slaveserver(const char *server)
{
    cfg_set_option_value(CAPWAPC_CFG_OPTION_SLASER_TUPLE, server);
    return 0;
}

int capwapc_undo_slaveserver(void)
{
    cfg_del_option(CAPWAPC_CFG_OPTION_SLASER_TUPLE);
    return 0;
}

int capwapc_set_echointv(int echointv)
{
    cfg_set_option_value_int(CAPWAPC_CFG_OPTION_ECHOINTV_TUPLE, echointv);
    return 0;
}

int capwapc_set_mtu(int mtu)
{
    cfg_set_option_value_int(CAPWAPC_CFG_OPTION_MTU_TUPLE, mtu);
    return 0;
}

int capwapc_set_masterserver(const char *server)
{
    cfg_set_option_value(CAPWAPC_CFG_OPTION_MASSER_TUPLE, server);
    return 0;
}

int capwapc_undo_masterserver(void)
{
    cfg_del_option(CAPWAPC_CFG_OPTION_MASSER_TUPLE);
    return 0;
}

int capwapc_set_ctrlport(int ctrlport)
{
    cfg_set_option_value_int(CAPWAPC_CFG_OPTION_CTRLPORT_TUPLE, ctrlport);
    return 0;
}

