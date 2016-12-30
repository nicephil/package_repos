#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "services/cfg_services.h"
#include "services/wlan_services.h"

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
        if (!strcmp(s_cur->type, WIFI_CFG_SECTION_DEVICE)) {
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

int wlan_set_country(const char *country)
{
    return 0;
}

int wlan_undo_country(void)
{
    return 0;
}

int wlan_get_country(char *country)
{
    return 0;
}
