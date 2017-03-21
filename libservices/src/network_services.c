#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


#include "services/network_services.h"


int get_manage_ifinfo(interface_info *info)
{
    return 0;
}

int network_set_enable(const char *name, int enable)
{
    if (!strcmp(name, "wifi0")) {
        wlan_set_radio_enable(0, enable?1:0);
    } else if (!strcmp(name, "wifi1")) {
        wlan_set_radio_enable(1, enable?1:0);
    }
    return 0;
}
