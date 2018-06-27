#include <syslog.h>

#include "services/log_services.h"
#include "services/cfg_services.h"


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
    //system.@system[0].conloglevel='5'
    //system.@system[0].klogconloglevel='5'
    //system.@system[0].log_type='file'
    //system.@system[0].log_file='/var/log/messages'
    //system.@system[0].log_size='128'
    //system.@system[0].log_remote='0'
    return 0;
}

int log_undo_infocenter(void)
{
    //
    return 0;
}

int log_set_hostip(const char *ip)
{
    cfg_set_option_value_int("system.@system[0].log_remote", 1);
    cfg_set_option_value("system.@system[0].log_ip", ip);
    return 0;
}

int log_undo_hostip(void)
{
    cfg_set_option_value_int("system.@system[0].log_remote", 0);
    cfg_set_option_value("system.@system[0].log_ip", DEFAULT_HOST_IP);
    return 0;
}

int log_set_hostlevel(int level)
{
    cfg_set_option_value_int("system.@system[0].conloglevel", level);
    cfg_set_option_value_int("system.@system[0].klogconloglevel", level);
    cfg_set_option_value_int("system.@system[0].cronloglevel", level);
    return 0;
}

int log_undo_hostlevel(void)
{
    cfg_set_option_value_int("system.@system[0].conloglevel", DEFAULT_HOST_LEVEL);
    cfg_set_option_value_int("system.@system[0].klogconloglevel", DEFAULT_HOST_LEVEL);
    cfg_set_option_value_int("system.@system[0].cronloglevel", DEFAULT_HOST_LEVEL);
    return 0;
}

int log_enable_buffer(void)
{
    cfg_set_option_value("system.@system[0].log_type", "circular");
    return 0;
}

int log_undo_buffer(void)
{
    cfg_set_option_value("system.@system[0].log_type", "file");
    return 0;
}

int log_set_bufferlevel(int level)
{
    cfg_set_option_value_int("system.@system[0].conloglevel", DEFAULT_HOST_LEVEL);
    cfg_set_option_value_int("system.@system[0].klogconloglevel", DEFAULT_HOST_LEVEL);
    cfg_set_option_value_int("system.@system[0].cronloglevel", DEFAULT_HOST_LEVEL);
    return 0;
}


int log_apply_all(int enabled)
{
    return 0;
    if (enabled) {
        system("/etc/init.d/boot restart&");
    } else {
        system("/etc/init.d/boot stop&");
    }
    return 0;
}

