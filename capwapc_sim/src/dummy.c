#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "dummy.h"

static struct product_info g_product_info = {
    .company            = {"Oakridge"},
    .production         = {"Oakridge AP"},
    .model              = {"WL8200-IT2"},
    .mac                = {"34:CD:6D:E0:34:6D"},
    .bootloader_version = {"1.0.0"},
    .software_version   = {"V200R001"},
    .software_inner_version = {"V200"},
    .hardware_version   = {"1.0.0"},
    .serial             = {"32A7D16Z0151617"},
};

void set_product_mac(const char *mac)
{
    strncpy(g_product_info.mac, mac, sizeof(g_product_info.mac) - 1);
}

void set_product_sn(const char *sn)
{
    strncpy(g_product_info.serial, sn, sizeof(g_product_info.serial) - 1);
}

int cfg_get_product_info(struct product_info * info)
{
    memcpy(info, &g_product_info, sizeof(struct product_info));
    return 0;
}

int vlan_get_manage_vlaninfo(interface_info *info)
{
    return 0;
}

struct dc_handle_result {
    int  code;
    char key[32];
} g_handle_result;



char *dc_get_handresult(void)
{
#define HANDLE_RESULT   "{\"code\": 0}"
    char *result;

    result = (char *)malloc(strlen(HANDLE_RESULT) + 1);

    strcpy(result, HANDLE_RESULT);
    
    return result;
}

int dc_json_machine(const char *data)
{
    return 0;
}

static int g_hanndle_doing = 0;
int dc_is_handle_doing(void)
{
    return (g_hanndle_doing == 1);
}
