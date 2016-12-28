#include <uci.h>
#include <string.h>
#include <stdlib.h>

#include "services/misc_services.h"

static int g_init = 0;

static struct product_info g_info;

int cfg_get_product_info(struct product_info * info)
{
    if (g_init) {
        memcpy(info, &g_info, sizeof(struct product_info));
    }
    struct uci_context *ctx;
    struct uci_package *p;
    struct uci_element *e1, *e2;

    memset(info, 0, sizeof(*info));

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    uci_load(ctx, PRODUCTINFO_CFG_PACKAGE, &p);

    uci_foreach_element(&p->sections, e1) {
        struct uci_section *s_cur = uci_to_section(e1);
        uci_foreach_element(&s_cur->options, e2) {
            struct uci_option *o_cur = uci_to_option(e2);
            if (o_cur->type == UCI_TYPE_STRING) {
                if (!strcmp(o_cur->e.name, PRODUCTINFO_OPTION_PRODUCTION)) {
                    strncpy(g_info.production, o_cur->v.string, sizeof(info->production));
                    strncpy(g_info.production, o_cur->v.string, sizeof(info->production));
                    strncpy(g_info.model, o_cur->v.string, sizeof(info->model));
                } else if (!strcmp(o_cur->e.name, PRODUCTINFO_OPTION_SERIAL)) {
                    strncpy(g_info.serial, o_cur->v.string, sizeof(info->serial));
                } else if (!strcmp(o_cur->e.name, PRODUCTINFO_OPTION_MAC)) {
                    strncpy(g_info.mac, o_cur->v.string, sizeof(info->mac));
                }
            }
        }
    }

    memcpy(info, &g_info, sizeof(struct product_info));
    uci_unload(ctx, p);
    uci_free_context(ctx);
    g_init = 1;
    return 0;
}

int if_get_radio_count (int *count)
{
    int max_count = 0;
    struct uci_context *ctx;
    struct uci_package *p;
    struct uci_element *e1, *e2;

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    uci_load(ctx, WIFI_CFG_PACKAGE, &p);

    uci_foreach_element(&p->sections, e1) {
        struct uci_section *s_cur = uci_to_section(e1);
        if (!strcmp(s_cur->e.name, WIFI_SECTION_DEVICE)) {
            uci_foreach_element(&s_cur->options, e2) {
                struct uci_option *o_cur = uci_to_option(e2);
                if (!strcmp(o_cur->e.name, WIFI_OPTION_ENABLE)) {
                    if (!strcmp(o_cur->v.string, "0")) {
                        max_count ++;
                    }
                } else {
                    max_count ++;
                }
            }
        }
    }

    *count = max_count;

    uci_unload(ctx, p);
    uci_free_context(ctx);
    return 0;
}

