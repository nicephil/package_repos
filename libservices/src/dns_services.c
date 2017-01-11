
#include "services/dns_services.h"
#include "services/cfg_services.h"

int dns_set_global(struct in_addr dns)
{
    //network.loopback.dns='2.2.2.4' '4.4.8.8'
    cfg_add_option_list_value("network.loopback.dns", inet_ntoa(dns));

    return 0;
}

int dns_undo_global(struct in_addr dns)
{
    //network.loopback.dns='2.2.2.4' '4.4.8.8'
    char tuple[128];
    sprintf(tuple, "network.loopback.dns=%s", inet_ntoa(dns));
    cfg_del_option_list_value(tuple);

    return 0;
}


int dns_undo_global_all(void)
{
    //network.loopback.dns='2.2.2.4' '4.4.8.8'
    cfg_del_option("network.loopback.dns=0");

    return 0;
}

int dns_get_global(struct in_addr * dns)
{
    return 0;
}

