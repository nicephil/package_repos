#include "services/ntpclient_services.h"

int ntpclient_enabled(void)
{
    //system.ntp.enable_server='1'
    cfg_set_option_value_int("system.ntp.enable_server", 1);

    system("/etc/init.d/sysntpd restart&");
    return 0;
}

int ntpclient_disabled(void)
{
    system("/etc/init.d/sysntpd stop&");

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
    cfg_add_section_with_name_type("system", "ntp", "timeserver");
    return 0;
}

int ntpclient_set_update_period(unsigned int value)
{
    return 0;
}

int ntpclient_get_defcfg(struct ntpclient_info *defcfg)
{
    defcfg->num = 2; 
    defcfg->enabled = 1;
    defcfg->period = 5;
    strcpy(defcfg->server[0], DEFAULT_NTP_SERVER1);
    strcpy(defcfg->server[1], DEFAULT_NTP_SERVER2);
    return 0;
}

