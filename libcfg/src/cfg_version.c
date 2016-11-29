#include <stdlib.h>
#include <stdio.h>
#include <sys/file.h>
#include <string.h>

#define LOCAL_CFG_VERSION 0xffffffff
#define CFG_VERSION_FILE  "/var/run/cfg_version"

struct cfg_verctrl {
    int version;
    int ifnotify;
};

static struct cfg_verctrl g_cfg_version = {
    .version = 0,
    .ifnotify = 1,
};

void cfg_set_version(int version)
{
    FILE *fp;
    char ver_line[32];
    
    g_cfg_version.version = version;

    if((fp = fopen(CFG_VERSION_FILE, "w")) == NULL) {
        return;
	}
    sprintf(ver_line, "%d", version);
    fwrite(ver_line, strlen(ver_line), 1, fp);
    fclose(fp);
}

int cfg_get_version(void) 
{
    FILE *fp;
    char ver_line[32];
    
    if((fp = fopen(CFG_VERSION_FILE, "r")) == NULL) {
        return g_cfg_version.version;
	}

    if (fgets(ver_line, sizeof(ver_line) - 1, fp) != NULL) {
        g_cfg_version.version = atoi(ver_line);
    }
    fclose(fp);

    return g_cfg_version.version;
}

void cfg_disable_version_notice(void)
{
    g_cfg_version.ifnotify = 0;
}

void cfg_enable_version_notice(void)
{
    g_cfg_version.ifnotify = 1;
}

void cfg_update_notice(void)
{
    if (g_cfg_version.ifnotify) {
       cfg_set_version(LOCAL_CFG_VERSION);    
    }
}
