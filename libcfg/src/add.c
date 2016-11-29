#include "cfg.h"
#include <unistd.h>
#include <errno.h>
int cfg_add_row(const char * table,
        const char * id)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char    name[128];

    if (table == NULL || id == NULL) {
        return -EINVAL;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }

    sprintf(name, "%s.%s=%s", table, id, id);
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_free_context(ctx);
        return -1;
    }

    cfg_set(ctx, &ptr);

    strcpy(name, table);
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_free_context(ctx);
        return -1;
    }

    cfg_commit(ctx, &ptr.p, false);

    cfg_free_context(ctx);
    return 0;
}

int main(void)
{
    cfg_add_row("interface", "VLAN1");

    return 0;
}
