#include "services/ntpclient_services.h"

int ntpclient_enabled(void)
{
    //system.ntp.enable_server='1'
    cfg_set_option_value_int("system.ntp.enable_server", 1);
    return 0;
}

int ntpclient_disabled(void)
{
    cfg_set_option_value_int("system.ntp.enable_server", 0);
    return 0;
}

int ntpclient_add_server(const char *server)
{
    //system.ntp.server='0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org' '2.openwrt.pool.ntp.org' '3.openwrt.pool.ntp.org'
    cfg_add_option_list_value("system.ntp.server", server);
    return 0;
}

int ntpclient_undo_all_server(void)
{
    //system.ntp=timeserver
    cfg_del_section("system.ntp");
    cfg_add_section_with_type_name("system", "ntp", "timeserver");
    return 0;
}

int ntpclient_set_update_period(unsigned int value)
{
    return 0;
}

int ntpclient_get_defcfg(struct ntpclient_info *defcfg)
{
    defcfg->num = 1; 
    defcfg->enabled = 1;
    defcfg->period = 5;
    strcpy(defcfg->server[0], "ntp.oakridge.io");
    return 0;
}

