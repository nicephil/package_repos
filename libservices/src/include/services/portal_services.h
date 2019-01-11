#ifndef __PORTAL_SERVICES_H_
#define __PORTAL_SERVICES_H_

/* following macro duplicate with portal_public.h because those modules does not complied now.
 * it will be replaced by including header file
 */
#define PORTAL_NAME_MAX_LENGTH      64
#define PORTAL_URI_MAX              128
#define PORTAL_MAX_IP_ACCESS_LIST   512
#define PORTAL_MAX_HOST_ACCESS_LIST 10
#define PORTAL_HOST_LEN_MAX         64
#define PORTAL_MAX_IP_ACCESS_ONCE   10
#define PORTAL_DNSSET_MAX           32


struct white_iplist 
{
    unsigned int ip;
    int masklen;
};

struct portal_scheme_cfg
{
	int enable;
	unsigned int auth_ip;
	unsigned int wechat_ip;
	char scheme_name[PORTAL_NAME_MAX_LENGTH + 1]; 
	char uri_path[PORTAL_URI_MAX + 1];
    int ip_num;
	struct white_iplist ip_list[PORTAL_MAX_IP_ACCESS_LIST];
	int domain_num;
    char domain_list[PORTAL_MAX_HOST_ACCESS_LIST][PORTAL_HOST_LEN_MAX + 1];
    char dns_set[PORTAL_DNSSET_MAX+1];
};

struct portal_schemes
{
    int num;	
    struct portal_scheme_cfg *config;
};

extern int portal_scheme_create(char * name);
extern int portal_scheme_destroy(char * name);
extern int portal_scheme_enable(char * name);
extern int portal_scheme_disable(char * name);
extern int portal_scheme_add_ipacl(char * name, char *ip, unsigned int cidr);
extern int portal_scheme_del_ipacl(char * name, char *ip, unsigned int cidr);
extern int portal_scheme_uri(char * name, char *uri);
extern int portal_scheme_blackip(char * name, char *authip, char *wechatip);
extern int portal_decompile( int fd );
extern int portal_scheme_flush_ipacl(char * name);

#define PORTAL_SCHEME_CFG_PACKAGE "portal"
#define PORTAL_SCHEME_MAX_SIZE 16
extern int portal_scheme_get_all(struct portal_schemes *schemes);
extern void portal_scheme_free_all(struct portal_schemes *schemes);
extern int portal_scheme_undo_dnsset(char * portal_scheme);
extern int portal_scheme_set_dnsset(char * portal_scheme, char *set_name);
extern int wlan_set_portal_scheme(int service_template, char * portal_scheme);
extern int wlan_undo_portal_scheme(int service_template);
extern int dump_portal_scheme_basic(int writefd, char *scheme_name);
extern int dump_portal_scheme_ipacl(int writefd, char *scheme_name);
extern int dump_portal_scheme_sta(int writefd, char *scheme_name);
extern int portal_scheme_del_sta(char * scheme_name, char * clientmac);
extern int portald_scheme_update_domain(char * domain_name);
extern int portald_scheme_update_domain_id(int domain_id);
extern int portald_scheme_update_domain_id_str(char * domain_id);
extern int portald_scheme_update_survive_mode(int survive_mode);
extern int portald_scheme_update_business_id(int business_id);
extern int portald_scheme_update_auth_url(char *auth_url);
extern int portal_scheme_authentication(char * scheme_name, char * clientmac, unsigned int time);
extern int portal_preauth_enable(void);
extern int portal_preauth_disable(void);
#endif /* __PORTAL_SERVICES_H */

