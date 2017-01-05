#include <uci.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "services/cfg_services.h"

int cfg_visit_package(const char *package_tuple, 
        int (*visitor)(struct uci_package *p, void *arg),
        void *arg)
{
    struct uci_context *ctx = NULL;
    struct uci_package *p = NULL;
    int ret = 0;

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    uci_load(ctx, package_tuple, &p);
    if(!p) {
        syslog(LOG_ERR, "no such package:%s\n", package_tuple);
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

int cfg_visit_section(const char *section_tuple, 
        int (*visitor)(struct uci_section *s, void *arg),
        void *arg)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple = strdup(section_tuple);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    ret = visitor(ptr.s, arg);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;
}


int cfg_get_option_value(const char *option_tuple, char *value, int len)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple = strdup(option_tuple);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }
    
    if (ptr.o->type == UCI_TYPE_STRING) {
        strncpy(value, ptr.o->v.string, len-1);
        value[len-1] = '\0';
    }

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;
}

int cfg_set_option_value(const char *option_tuple, const char *value)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple;

    assert(option_tuple);
    assert(value);

    tuple = malloc(strlen(option_tuple)+strlen(value)+10);
    sprintf(tuple, "%s=%s", option_tuple, value);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.p) || !(ptr.s)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }
    
    uci_set(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;
}

int cfg_set_option_value_int(const char *option_tuple, int value)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple;

    tuple = malloc(strlen(option_tuple)+43);
    sprintf(tuple, "%s=%d", option_tuple, value);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.p) || !(ptr.s)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }
    
    uci_set(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;

}

int cfg_add_option_list_value(const char *option_tuple, char *list_value)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple;

    tuple = malloc(strlen(option_tuple)+strlen(list_value)+10);
    sprintf(tuple, "%s=%s", option_tuple, list_value);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.p) || !(ptr.s)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    uci_add_list(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;
}

int cfg_del_option_list_value(const char *option_tuple)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple = strdup(option_tuple);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    uci_del_list(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;
}

int cfg_del_option(const char *option_tuple)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple = strdup(option_tuple);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }
    
    uci_delete(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;
}

int cfg_add_section_with_type_name(const char *package_tuple, const char *section_type, const char *section_name)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple;

     tuple = malloc(strlen(package_tuple)+strlen(section_name)+strlen(section_type)+10);
     sprintf(tuple, "%s.%s=%s", package_tuple, section_type, section_name);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.p)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }
    
    uci_set(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;

}

int cfg_add_section(const char *package_tuple, const char *section_type_name)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple;

    tuple = malloc(strlen(package_tuple)+strlen(section_type_name)+10);
    sprintf(tuple, "%s.%s=%s", package_tuple, section_type_name, section_type_name);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.p)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }
    
    uci_set(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;

}

int cfg_del_section(const char *section_tuple)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr = {0};
    int ret = 0;
    char *tuple = strdup(section_tuple);

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
        syslog(LOG_ERR, "no such field:%s\n", tuple);
        ret = -1;
        goto _free;
    }

    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        syslog(LOG_ERR, "no such complete field:%s\n", tuple);
        ret = -1;
        goto _free;
    }
    
    uci_delete(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);

_free:
    if (ctx && ptr.p) {
        uci_unload(ctx, ptr.p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    if (tuple) {
        free(tuple);
    }
    return ret;
}


#define LOCAL_CFG_VERSION 0xffffffff
struct cfg_verctrl {
    int version;
    int ifnotify;
};

static struct cfg_verctrl g_cfg_version = {
    .version = 0,
    .ifnotify = 1,
};

int g_cfg_init = 0;

void cfg_set_version(int version)
{
    char value[33];
    sprintf(value, "%d", version);
    cfg_set_option_value(OKCFG_OPTION_VERSION_STR, value);
    g_cfg_version.version = version;
    return;
}

int cfg_get_version(void) 
{
    char value[33] = {0};

    if (g_cfg_init) {
        return g_cfg_version.version;
    }

    cfg_get_option_value(OKCFG_OPTION_VERSION_STR, value, sizeof(value));
    g_cfg_version.version = atoi(value);

    return g_cfg_version.version;
}

void cfg_disable_version_notice(void)
{
    g_cfg_version.ifnotify = 0;
}

void cfg_enable_version_notice(void)
{
    g_cfg_version.ifnotify = 1;
}

void cfg_update_notice(void)
{
    if (g_cfg_version.ifnotify) {
       cfg_set_version(LOCAL_CFG_VERSION);    
    }
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


