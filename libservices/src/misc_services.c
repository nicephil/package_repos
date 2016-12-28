#include <uci.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "services/misc_services.h"

int uci_visit_package(const char * package, 
        int (*visitor)(struct uci_package *, void *arg),
        void * arg)
{
    struct uci_context *ctx = NULL;
    struct uci_package *p = NULL;
    int ret = 0;

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    uci_load(ctx, package, &p);
    if(!p) {
        syslog(LOG_ERR, "no such package:%s\n", package);
        ret = -1;
        goto _free;
    }

    ret = visitor(p, arg);

_free:
    if (ctx && p) {
        uci_unload(ctx, p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    return ret;
}

static int g_pinfo_init = 0;

static struct product_info g_pinfo = {
    .company            = {"Oakridge"},
    .production         = {"Oakridge AP"},
    .model              = {"AP4602"},
    .mac                = {"34:CD:6D:E0:34:6D"},
    .bootloader_version = {"1.0.0"},
    .software_version   = {"V200R001"},
    .software_inner_version = {"V200"},
    .hardware_version   = {"1.0.0"},
    .serial             = {"32A7D16Z0151617"},
};


int cfg_get_product_info(struct product_info * info)
{
    if (g_pinfo_init) {
        memcpy(info, &g_pinfo, sizeof(struct product_info));
        return 0;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *p = NULL;
    struct uci_element *e1 = NULL;
    struct uci_element *e2 = NULL;
    int ret = 0;

    memset(info, 0, sizeof(struct product_info));

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    uci_load(ctx, PRODUCTINFO_CFG_PACKAGE, &p);
    if (!p) {
        syslog(LOG_ERR, "no such package:%s\n", PRODUCTINFO_CFG_PACKAGE);
        ret = -1;
        goto _free;
    }

    uci_foreach_element(&p->sections, e1) {
        struct uci_section *s_cur = uci_to_section(e1);
        //printf("s_cur:%s-%s\n", s_cur->e.name, s_cur->type);
        uci_foreach_element(&s_cur->options, e2) {
            struct uci_option *o_cur = uci_to_option(e2);
            //printf("o_cur:%s-%s\n", o_cur->e.name, o_cur->v.string);
            if (!strcmp(o_cur->e.name, PRODUCTINFO_OPTION_PRODUCTION)) {
                strncpy(info->production, o_cur->v.string, sizeof(info->production));
                strncpy(info->production, o_cur->v.string, sizeof(info->production));
                strncpy(info->model, o_cur->v.string, sizeof(info->model));
            } else if (!strcmp(o_cur->e.name, PRODUCTINFO_OPTION_SERIAL)) {
                strncpy(info->serial, o_cur->v.string, sizeof(info->serial));
            } else if (!strcmp(o_cur->e.name, PRODUCTINFO_OPTION_MAC)) {
                strncpy(info->mac, o_cur->v.string, sizeof(info->mac));
            }
        }
    }

    memcpy(&g_pinfo, info, sizeof(struct product_info));
    g_pinfo_init = 1;

_free:
    if (ctx && p) {
        uci_unload(ctx, p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    return ret;
}

int if_get_radio_count (int *count)
{
    struct uci_context *ctx = NULL;
    struct uci_package *p = NULL;
    struct uci_element *e = NULL;
    int ret = 0;
    *count = 0;

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    uci_load(ctx, WIFI_CFG_PACKAGE, &p);
    if(!p) {
        syslog(LOG_ERR, "no such package:%s\n", WIFI_CFG_PACKAGE);
        ret = -1;
        goto _free;
    }

    uci_foreach_element(&p->sections, e) {
        struct uci_section *s_cur = uci_to_section(e);
        if (!strcmp(s_cur->type, WIFI_SECTION_DEVICE)) {
            *count ++;
        }
    }

_free:
    if (ctx && p) {
        uci_unload(ctx, p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    return ret;
}

