#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#if !OK_PATCH
#include "cfg/cfg.h"
#include "cmp/cmp_pub.h"
#include "capwapc_services.h"
#include "../plugins/capwapc.h"

typedef struct capwapc_entry {
    int cmp_id;    
    CMP_CMOINFO_S item;
} capwapc_entry;

static int do_capwapc(capwapc_entry entry, int op)
{
    void *msg, *reply;
    int fd, ret;
    unsigned long err, index;

    ret = CMP_Init(&fd, &msg, op, entry.cmp_id);
    if (CMP_ERR_NO_ERR != ret) {
        return ret;
    }
    
    CMP_AppendPara2Msg(msg, &(entry.item));
            
    CMP_SetDaemonPort(msg, CMP_SERVICE_NAME, strlen(CMP_SERVICE_NAME));
    ret = CMP_SendMsg(fd, msg, &reply);

    CMP_IpcClose(fd);
    CMP_FreeMsg(msg);

    if (CMP_ERR_NO_ERR != ret) {
        return ret;
    }
    
    CMP_GetMsgError(reply, &err, &index);
    CMP_FreeMsg(reply);
    
    return err;
}

int capwapc_enable(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_GLOBAL;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_ENABLE;
    entry.item.ulLen = sizeof(int);
    entry.item.unValue.uiValue = 1;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_disable(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_GLOBAL;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_ENABLE;
    entry.item.ulLen = sizeof(int);
    entry.item.unValue.uiValue = 0;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_set_location(const char *location)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_GLOBAL;

    entry.item.enCMOType = CMO_OCTET_STRING;
    entry.item.ulCMO = CAPWAPC_CMO_LOCATION;
    entry.item.ulLen = (CMP_CMO_LENGTH > strlen(location)? 
                    strlen(location) : CMP_CMO_LENGTH);
    strncpy(entry.item.unValue.szValue, location, entry.item.ulLen);
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_location(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_GLOBAL;
    entry.item.ulCMO = CAPWAPC_CMO_LOCATION;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_domain(const char *domain)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_GLOBAL;

    entry.item.enCMOType = CMO_OCTET_STRING;
    entry.item.ulCMO = CAPWAPC_CMO_DOMAIN;
    entry.item.ulLen = (CMP_CMO_LENGTH > strlen(domain)? 
                    strlen(domain) : CMP_CMO_LENGTH);
    strncpy(entry.item.unValue.szValue, domain, entry.item.ulLen);
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_domain(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_GLOBAL;
    entry.item.ulCMO = CAPWAPC_CMO_DOMAIN;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_get_domain(char *domain, int len)
{
    return cfg_get_value(CAPWAPC_CFG_TABLE, CAPWAPC_CFG_ID_GLOBAL,  
                CAPWAPC_CFG_FIELD_DOMAIN, domain, len);
}

int capwapc_set_masterserver(const char *server)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_SERVER;

    entry.item.enCMOType = CMO_OCTET_STRING;
    entry.item.ulCMO = CAPWAPC_CMO_MASTER_SERVER;
    entry.item.ulLen = (CMP_CMO_LENGTH > strlen(server)? 
                    strlen(server) : CMP_CMO_LENGTH);
    strncpy(entry.item.unValue.szValue, server, entry.item.ulLen);
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_masterserver(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_SERVER;
    entry.item.ulCMO = CAPWAPC_CMO_MASTER_SERVER;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_slaveserver(const char *server)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_SERVER;

    entry.item.enCMOType = CMO_OCTET_STRING;
    entry.item.ulCMO = CAPWAPC_CMO_SLAVER_SERVER;
    entry.item.ulLen = (CMP_CMO_LENGTH > strlen(server)? 
                    strlen(server) : CMP_CMO_LENGTH);
    strncpy(entry.item.unValue.szValue, server, entry.item.ulLen);
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_slaveserver(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_SERVER;
    entry.item.ulCMO = CAPWAPC_CMO_SLAVER_SERVER;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_defaultserver(const char *server)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_SERVER;

    entry.item.enCMOType = CMO_OCTET_STRING;
    entry.item.ulCMO = CAPWAPC_CMO_DEFAULT_SERVER;
    entry.item.ulLen = (CMP_CMO_LENGTH > strlen(server)? 
                    strlen(server) : CMP_CMO_LENGTH);
    strncpy(entry.item.unValue.szValue, server, entry.item.ulLen);
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_defaultserver(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_SERVER;
    entry.item.ulCMO = CAPWAPC_CMO_DEFAULT_SERVER;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_ctrlport(int ctrlport)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_SERVER;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_CONTROL_PORT;
    entry.item.ulLen = sizeof(ctrlport);
    entry.item.unValue.uiValue = ctrlport;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_ctrlport(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_SERVER;
    entry.item.ulCMO = CAPWAPC_CMO_CONTROL_PORT;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_mtu(int mtu)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_MTU;
    entry.item.ulLen = sizeof(mtu);
    entry.item.unValue.uiValue = mtu;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_mtu(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_MTU;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_discintv(int discintv)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_DISCINTV;
    entry.item.ulLen = sizeof(discintv);
    entry.item.unValue.uiValue = discintv;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_discintv(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_DISCINTV;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_maxdiscintv(int max_discintv)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_MAXDISCINTV;
    entry.item.ulLen = sizeof(max_discintv);
    entry.item.unValue.uiValue = max_discintv;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_maxdiscintv(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_MAXDISCINTV;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_echointv(int echointv)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_ECHOINTV;
    entry.item.ulLen = sizeof(echointv);
    entry.item.unValue.uiValue = echointv;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_echointv(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_ECHOINTV;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_retranintv(int retranintv)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_RETRANINTV;
    entry.item.ulLen = sizeof(retranintv);
    entry.item.unValue.uiValue = retranintv;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_retranintv(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_RETRANINTV;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_silentintv(int silentintv)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_SILENTINTV;
    entry.item.ulLen = sizeof(silentintv);
    entry.item.unValue.uiValue = silentintv;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_silentintv(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_SILENTINTV;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_jointimeout(int jointimeout)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_JOINTIMEOUT;
    entry.item.ulLen = sizeof(jointimeout);
    entry.item.unValue.uiValue = jointimeout;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_jointimeout(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_JOINTIMEOUT;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_maxdisces(int maxdisces)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_MAXDISCS;
    entry.item.ulLen = sizeof(maxdisces);
    entry.item.unValue.uiValue = maxdisces;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_maxdisces(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_MAXDISCS;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_maxretran(int maxretran)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_MAXRETRANS;
    entry.item.ulLen = sizeof(maxretran);
    entry.item.unValue.uiValue = maxretran;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_undo_maxretran(void)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_WTP;
    entry.item.ulCMO = CAPWAPC_CMO_WTP_MAXRETRANS;
    
    return do_capwapc(entry, OP_UNDO);
}

int capwapc_set_forceexec(int force)
{
    capwapc_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.cmp_id = CAPWAPC_CMP_GLOBAL;

    entry.item.enCMOType = CMO_INTEGER;
    entry.item.ulCMO = CAPWAPC_CMO_FORCEDOEN;
    entry.item.ulLen = sizeof(force);
    entry.item.unValue.uiValue = force;
    
    return do_capwapc(entry, OP_SET);
}

int capwapc_restart(void)
{
    int ret;
    
    ret = capwapc_disable();
    ret += capwapc_enable();

    return ret;
}

int capwapc_get_status(struct capwapc_status *status)
{
    void *msg, *reply;
    int fd, ret;
    unsigned long err, index;
    CMP_CMOINFO_S item;

    ret = CMP_Init(&fd, &msg, OP_GET, CAPWAPC_CMP_GLOBAL);
    if (CMP_ERR_NO_ERR != ret) {
        return ret;
    }

    memset(&item, 0, sizeof(item));
    item.ulCMO = CAPWAPC_CMO_STATUS;
    CMP_AppendPara2Msg(msg, &(item));
            
    CMP_SetDaemonPort(msg, CMP_SERVICE_NAME, strlen(CMP_SERVICE_NAME));
    ret = CMP_SendMsg(fd, msg, &reply);

    CMP_IpcClose(fd);
    CMP_FreeMsg(msg);

    if (CMP_ERR_NO_ERR != ret) {
        return ret;
    }
    
    CMP_GetMsgError(reply, &err, &index);
    if (CMP_ERR_NO_ERR != err) {
       goto FAILED; 
    }

    if (CMP_GetAllParaNum(reply) < 1) {
        err = CMP_ERR_NO_SUCH_INSTANCE;
        goto FAILED;
    }

    CMP_GetParaFromMsg(reply, 0, &item);
    if (item.ulLen != sizeof(*status)) {
        err = CMP_ERR_BAD_VALUE;
        goto FAILED;
    }
    
    memcpy(status, item.unValue.szValue, item.ulLen);

FAILED:    
    CMP_FreeMsg(reply);
    
    return err;
}

static int capwap_config_info(struct cfg_package * p, void * arg)
{
    struct cfg_element *e1, *e2;
    struct cfg_section *s;
    struct cfg_option *o;

    capwapc_config *info = (capwapc_config *)arg;

    cfg_foreach_element(&p->sections, e1) {
        s = cfg_to_section(e1);
        cfg_foreach_element(&s->options, e2) {
            o = cfg_to_option(e2);
            if (o->type == CFG_TYPE_STRING) {   
                if (!strcmp(o->e.name, "enable"))  {
                    info->enable = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "location"))  {
                    strncpy(info->location, o->v.string, sizeof(info->location) - 1);
                }else if (!strcmp(o->e.name, "domain"))  {
                    strncpy(info->domain, o->v.string, sizeof(info->domain) - 1);
                }else if (!strcmp(o->e.name, "control_port"))  {
                    info->ctrl_port= atoi(o->v.string);
                }else if (!strcmp(o->e.name, "default_server"))  {
                    strncpy(info->def_server, o->v.string, sizeof(info->def_server) - 1);
                }else if (!strcmp(o->e.name, "master_server"))  {
                    strncpy(info->mas_server, o->v.string, sizeof(info->mas_server) - 1);
                }else if (!strcmp(o->e.name, "slaver_server"))  {
                    strncpy(info->sla_server, o->v.string, sizeof(info->sla_server) - 1);
                }else if (!strcmp(o->e.name, "discovery_interval"))  {
                    info->disc_intv = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "echo_interval"))  {
                    info->echo_intv = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "silent_interval"))  {
                    info->silent_intv = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "max_discoveries"))  {
                    info->max_disces = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "max_retransmit"))  {
                    info->max_retran = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "mtu"))  {
                    info->mtu = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "max_discovery_interval"))  {
                    info->maxdisc_intv = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "retransmit_interval"))  {
                    info->retran_intv = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "join_timeout"))  {
                    info->join_timeout = atoi(o->v.string);
                }
            }
        }
    }

    return 0;
}


int capwapc_decompile(int fd)
{
    capwapc_config *capwapinfo;
    int len = 0;
    char cmd[128] = {};
    
    capwapinfo = malloc(sizeof(capwapc_config));
    
    memset(capwapinfo, 0, sizeof(capwapc_config));

    cfg_visit_package(CAPWAPC_MODULE, capwap_config_info, capwapinfo);

    if(strlen(capwapinfo->location) > 0){
        write(fd, "!\n", 2);
        memset(cmd, 0, sizeof(cmd));
        len = sprintf(cmd, "device-location %s\n", capwapinfo->location);
        write(fd, cmd, len);
    }

    if(strlen(capwapinfo->domain) > 0){
        write(fd, "!\n", 2);
        memset(cmd, 0, sizeof(cmd));
        len = sprintf(cmd, "domain %s\n", capwapinfo->domain);
        write(fd, cmd, len);
    }
    
    
    write(fd, "!\n", 2);
    
    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "service capwap\n");
    write(fd, cmd, len);
        
    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  discovery-interval %d\n", capwapinfo->disc_intv);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  echo-interval %d\n", capwapinfo->echo_intv);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  join-timeout %d\n", capwapinfo->join_timeout);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  max-discoveries %d\n", capwapinfo->max_disces);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  max-discovery-interval %d\n", capwapinfo->maxdisc_intv);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  max-retransmit %d\n", capwapinfo->max_retran);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  mtu %d\n", capwapinfo->mtu);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  retransmit-interval %d\n", capwapinfo->retran_intv);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  silent-interval %d\n", capwapinfo->silent_intv);
    write(fd, cmd, len);

    if(strcmp(capwapinfo->mas_server, "")){
        memset(cmd, 0, sizeof(cmd));
        len = sprintf(cmd, "  master-server %s\n", capwapinfo->mas_server);
        write(fd, cmd, len);
    }

    if(strcmp(capwapinfo->sla_server, "")){
        memset(cmd, 0, sizeof(cmd));
        len = sprintf(cmd, "  slave-server %s\n", capwapinfo->sla_server);
        write(fd, cmd, len);
    }

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  default-server %s\n", capwapinfo->def_server);
    write(fd, cmd, len);

    memset(cmd, 0, sizeof(cmd));
    len = sprintf(cmd, "  control-port %d\n", capwapinfo->ctrl_port);
    write(fd, cmd, len);

    if(1 == capwapinfo->enable){
        memset(cmd, 0, sizeof(cmd));
        len = sprintf(cmd, "  service enable\n");
        write(fd, cmd, len);
    }else{
        memset(cmd, 0, sizeof(cmd));
        len = sprintf(cmd, "  service disable\n");
        write(fd, cmd, len);
    }

   

    free(capwapinfo);
    
    return 0;
}

int capwapc_get_curcfg(capwapc_config *curcfg)
{
    char buf[8];
    
    if (cfg_get_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_GLOBAL, CAPWAPC_CFG_FIELD_enable, 
        buf, sizeof(buf))) {
        return -1;
    }
    curcfg->enable = atoi(buf);

    if (cfg_get_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_SERVER, CAPWAPC_CFG_FIELD_MASSER, 
        curcfg->mas_server, sizeof(curcfg->mas_server))) {
        curcfg->mas_server[0] = 0;
    }

    if (cfg_get_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_SERVER, CAPWAPC_CFG_FIELD_SLASER, 
        curcfg->sla_server, sizeof(curcfg->sla_server))) {
        curcfg->sla_server[0] = 0;
    }
    
    if (cfg_get_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_SERVER, CAPWAPC_CFG_FIELD_CTRLPORT, 
        buf, sizeof(buf))) {
        return -1;
    }
    curcfg->ctrl_port = atoi(buf);

    if (cfg_get_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_WTP, CAPWAPC_CFG_FIELD_MTU, 
        buf, sizeof(buf))) {
        return -1;
    }
    curcfg->mtu = atoi(buf);

    if (cfg_get_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_WTP, CAPWAPC_CFG_FIELD_ECHOINTV, 
        buf, sizeof(buf))) {
        return -1;
    }
    curcfg->echo_intv = atoi(buf);

    return 0;
    /* yes, i don't care othre config, because NMS just can config those config now */
}


int capwapc_get_defcfg(capwapc_config *defcfg)
{
    char buf[8];
    
    if (cfg_get_default_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_GLOBAL, CAPWAPC_CFG_FIELD_enable, 
        buf, sizeof(buf))) {
        return -1;
    }
    defcfg->enable = atoi(buf);

    if (cfg_get_default_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_SERVER, CAPWAPC_CFG_FIELD_MASSER, 
        defcfg->mas_server, sizeof(defcfg->mas_server))) {
        defcfg->mas_server[0] = 0;
    }

    if (cfg_get_default_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_SERVER, CAPWAPC_CFG_FIELD_SLASER, 
        defcfg->sla_server, sizeof(defcfg->sla_server))) {
        defcfg->sla_server[0] = 0;
    }
    
    if (cfg_get_default_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_SERVER, CAPWAPC_CFG_FIELD_CTRLPORT, 
        buf, sizeof(buf))) {
        return -1;
    }
    defcfg->ctrl_port = atoi(buf);

    if (cfg_get_default_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_WTP, CAPWAPC_CFG_FIELD_MTU, 
        buf, sizeof(buf))) {
        return -1;
    }
    defcfg->mtu = atoi(buf);

    if (cfg_get_default_value(CAPWAPC_MODULE, CAPWAPC_CFG_ID_WTP, CAPWAPC_CFG_FIELD_ECHOINTV, 
        buf, sizeof(buf))) {
        return -1;
    }
    defcfg->echo_intv = atoi(buf);

    return 0;
    /* yes, i don't care othre config, because NMS just can config those config now */
}

//add by puyg: create tech_support file for capwap file 
#if 0
int show_capwap_info(int fd){
    struct capwapc_status status;
    const struct state_desc {
        capwapc_state_e state;
        char *desc;
    } state_desc[] = {
        {CAPWAPC_STATE_DISABLE,   "Disable"},
        {CAPWAPC_STATE_INIT,      "Init"},
        {CAPWAPC_STATE_SULKING,   "Sulking"},
        {CAPWAPC_STATE_DISCOVERY, "Discovery"},
        {CAPWAPC_STATE_JOIN,      "Join"},
        {CAPWAPC_STATE_CONFIGURE, "Configure"},
        {CAPWAPC_STATE_DATA_CHECK,"Data check"},
        {CAPWAPC_STATE_RUN,       "Run"},
        {CAPWAPC_STATE_RESET,     "Reset"}
    };
    int ret;
    int len = 0;
    char cmd[128] = {};

    memset(&status, 0, sizeof(status));
    if ((ret = capwapc_get_status(&status)) || 
        (status.state >= CAPWAPC_STATE_MAX || status.state < 0)) {
        len = sprintf(cmd, "capwap state: Unknow, %d\r\n", ret);
        write(fd, cmd, len);
        memset(cmd, 0, sizeof(cmd));
    }
    else {
        len = sprintf(cmd, "capwap   state: %s\r\n", state_desc[status.state].desc);
        write(fd, cmd, len);
        memset(cmd, 0, sizeof(cmd));
        if (strlen(status.server_name) > 0){
            len = sprintf(cmd, "server    name: %s\r\n", status.server_name);
            write(fd, cmd, len);
            memset(cmd, 0, sizeof(cmd));
        }
        if (strlen(status.server_addr) > 0){
            len = sprintf(cmd, "server address: %s\r\n", status.server_addr);
            write(fd, cmd, len);
            memset(cmd, 0, sizeof(cmd));
        }

        if (status.state == CAPWAPC_STATE_RUN) {
            struct sysinfo sys;
            int uptime, updays, uphours, upminutes;
            
            sysinfo(&sys);
            if (sys.uptime > status.uptime) {
                uptime = sys.uptime - status.uptime;
                updays = (int) uptime / (60 * 60 * 24);
                upminutes = (int) uptime / 60;
            	uphours = (upminutes / 60) % 24;
            	upminutes %= 60;

                memset(cmd, 0, sizeof(cmd));
                if (updays) {
                    len = sprintf(cmd, "Connected duration: %d day%s, %2d:%02d\r\n", 
                        updays, (updays != 1) ? "s" : "", uphours, upminutes);
                }
                else {
                    if (uphours)
                		len = sprintf(cmd, "Connected duration: %2d:%02d\r\n", uphours, upminutes);
                	else
                        len = sprintf(cmd, "Connected duration: %d min\r\n", upminutes);
                }
                
                write(fd, cmd, len);
            }
        }
    }
    return 0;
}
#endif

int capwapc_get_server_pri(char *server, int *pri)
{
    void *msg, *reply;
    int fd, ret, num;
    unsigned long err, index;    
    CMP_CMOINFO_S item;

    ret = CMP_Init(&fd, &msg, OP_GET, CAPWAPC_CMP_GLOBAL);
    if (CMP_ERR_NO_ERR != ret) {
        return ret;
    }

    memset(&item, 0, sizeof(item));
    item.ulCMO = CAPWAPC_CMO_PRIORITY;
    item.ulLen = strlen(server) + 1;
    strcpy(item.unValue.szValue, server);
    CMP_AppendPara2Msg(msg, &item);
            
    CMP_SetDaemonPort(msg, CMP_SERVICE_NAME, sizeof(CMP_SERVICE_NAME) - 1);
    ret = CMP_SendMsg(fd, msg, &reply);
    CMP_IpcClose(fd);
    CMP_FreeMsg(msg);

    if (ret != CMP_ERR_NO_ERR) {
        return ret;
    }
    
    CMP_GetMsgError(reply, &err, &index);
    num = CMP_GetAllParaNum(reply);
    if (err == CMP_ERR_NO_ERR && (num >= 1)) {
        CMP_CMOINFO_S   param;

        ret = CMP_GetParaFromMsg(reply, 0, &param);
        if (CMP_ERR_NO_ERR != ret) {
            err = -1;    
            goto out;
        }
        *pri = param.unValue.uiValue;
    }
out:    

    CMP_FreeMsg(reply);
    return err;

}
#endif
