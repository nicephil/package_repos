#include <uci.h>

#include "services/cfg_services.h"
#include "services/portal_services.h"

int portal_scheme_create(char * name)
{
    return 0;
}

int portal_scheme_destroy(char * name)
{
    return 0;
}

int portal_scheme_enable(char * name)
{
    return 0;
}

int portal_scheme_disable(char * name)
{
    return 0;
}

int portal_scheme_add_ipacl(char * name, char *ip, unsigned int cidr)
{
    return 0;
}

int portal_scheme_del_ipacl(char * name, char *ip, unsigned int cidr)
{
    return 0; 
}

int portal_scheme_flush_ipacl(char * name)
{
    return 0;
}


int portal_scheme_uri(char * name, char *uri)
{
    return 0;
}

int portal_scheme_blackip(char * name, char *authip, char *wechatip)
{
    return 0;
}

int portal_scheme_set_dnsset(char * portal_scheme, char *set_name)
{
    return 0;
}
int portal_scheme_undo_dnsset(char * portal_scheme)
{
    return 0;
}

int wlan_set_portal_scheme(int service_template, char * portal_scheme)
{
    return 0;
}

int wlan_undo_portal_scheme(int service_template)
{
    return 0;
}

int portal_scheme_decompile_iterator(struct cfg_package * p, void * arg)
{
    return 0;
}

int portal_decompile( int fd )
{
    return 0;
}

static int portal_scheme_iterator(struct cfg_package * p, void * arg)
{
    return 0;
}

int portal_scheme_get_all(struct portal_schemes *schemes)
{
    return 0;
}

void portal_scheme_free_all(struct portal_schemes *schemes)
{
}

static int portal_check_iterator(struct cfg_package * p, void * arg)
{
    return 1;
}

/*return 0 if exist , 1 (none)  if not */
static int if_portal_scheme_exist(char * name)
{

    return 0;
}

static void dumpif_name_by_index(int fd, int ifindex)
{
	return;
}
int dump_portal_scheme_basic(int writefd, char *scheme_name) 
{
	return 0;
}

int dump_portal_scheme_ipacl(int writefd, char *scheme_name) 
{
	return 0;
}

int dump_portal_scheme_sta(int writefd, char *scheme_name) 
{
	return 0;
}

int portal_scheme_del_sta(char * scheme_name, char * clientmac) 
{
	return 0;
}

int portald_scheme_update_domain(char * domain_name)
{
    if (!domain_name) {
        cfg_del_option(PORTALSCHEME_CFG_OPTION_DOMAIN_TUPLE);
    } else {
        cfg_set_option_value(PORTALSCHEME_CFG_OPTION_DOMAIN_TUPLE, domain_name);
    }
    return 0;
}

int portal_scheme_authentication(char * scheme_name, char * clientmac, unsigned int time) 
{
	return 0;
}

int portal_preauth_ctrl(int ctrl)
{
    return 0;
} 

int portal_preauth_enable(void) {
    return portal_preauth_ctrl(1);
}

int portal_preauth_disable(void) {
    return portal_preauth_ctrl(0);
}


