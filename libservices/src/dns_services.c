
#include "services/dns_services.h"

int dns_set_global(struct in_addr dns)
{
    //dns.DNS.dns='2.2.2.2'
    cfg_add_option_list_value("dns.DNS.dns", inet_ntoa(dns));
    return 0;
}

int dns_undo_global(struct in_addr dns)
{
    //dns.DNS.dns='2.2.2.2'
    char tuple[128];
    sprintf(tuple, "dns.DNS.dns=%s", inet_ntoa(dns));
    cfg_del_option_list_value(tuple);
    return 0;
}

int dns_undo_global_all(void)
{
    cfg_del_section(DNS_CFG_PACKAGE, "DNS");
    cfg_add_section(DNS_CFG_PACKAGE, "DNS");
    return 0;
}

int dns_get_global(struct in_addr * dns)
{
    return 0;
}
