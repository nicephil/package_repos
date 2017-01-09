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
    wlan_set_radio_enable(0, 1);
    wlan_set_radio_enable(1, 1);
    return 0;
}
