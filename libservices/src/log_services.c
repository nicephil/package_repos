#include <syslog.h>

#include "services/log_services.h"


int log_get_defcfg(log_infocenter *infocenter)
{
    log_infocenter info = {
        .center = {
            .enable = DEFAULT_INFOCENTER_ENABLE,  
        },
        .host = {
            .level  = DEFAULT_HOST_LEVEL,
            .ip     = {DEFAULT_HOST_IP},
        },
        .buffer = {
            .enable = DEFAULT_BUFFER_ENABLE,
            .level  = DEFAULT_BUFFER_LEVEL,
        },
        .terminal = {
            .enable = DEFAULT_TERMINAL_ENABLE,
            .level  = DEFAULT_TERMINAL_LEVEL,
        },
    };

    memcpy(infocenter, &info, sizeof(info));

    return 0;
}

int log_enable_infocenter(void)
{
    return 0;
}

int log_undo_infocenter(void)
{
    return 0;
}

int log_set_hostip(const char *ip)
{
    return 0;
}

int log_undo_hostip(void)
{
    return 0;
}

int log_set_hostlevel(int level)
{
    return 0;
}

int log_undo_hostlevel(void)
{
    return 0;
}

int log_enable_buffer(void)
{
    return 0;
}

int log_undo_buffer(void)
{
    return 0;
}

int log_set_bufferlevel(int level)
{
    return 0;
}



