#ifndef _AAA_SERVICES_H_
#define _AAA_SERVICES_H_

#include <arpa/inet.h>


#define CFG_RADIUS_SCHEME_PACKAGE "radius_scheme"

#define CFG_RADIUS_PRI_AUTH_IP      "primary_authentication_ip" 
#define CFG_RADIUS_PRI_AUTH_PORT    "primary_authentication_port" 
#define CFG_RADIUS_PRI_AUTH_KEY     "primary_authentication_key" 
#define CFG_RADIUS_PRI_AUTH_KEY_CRYPT     "primary_authentication_key_crypt" 
 
#define CFG_RADIUS_SEC_AUTH_IP      "secondary_authentication_ip" 
#define CFG_RADIUS_SEC_AUTH_PORT    "secondary_authentication_port" 
#define CFG_RADIUS_SEC_AUTH_KEY     "secondary_primary_authentication_key" 
#define CFG_RADIUS_SEC_AUTH_KEY_CRYPT     "secondary_authentication_key_crypt" 
 
#define CFG_RADIUS_PRI_ACCT_IP      "primary_accounting_ip"
#define CFG_RADIUS_PRI_ACCT_PORT    "primary_accounting_port" 
#define CFG_RADIUS_PRI_ACCT_KEY     "primary_accounting_key" 
#define CFG_RADIUS_PRI_ACCT_KEY_CRYPT     "primary_accounting_key_crypt" 
 
#define CFG_RADIUS_SEC_ACCT_IP      "secondary_accounting_ip" 
#define CFG_RADIUS_SEC_ACCT_PORT    "secondary_accounting_port" 
#define CFG_RADIUS_SEC_ACCT_KEY     "secondary_accounting_key" 
#define CFG_RADIUS_SEC_ACCT_KEY_CRYPT     "secondary_accounting_key_crypt"
                

#ifndef RADIUS_KEY
#define RADIUS_KEY 1
enum RADIUS_KEY_CRYPT {
    RADIUS_KEY_CRYPT_PLAIN = 0,
    RADIUS_KEY_CRYPT_CIPHER
};
#endif

extern int radius_scheme_create(const char * name);

extern int radius_scheme_set_pri_auth(const char * name, 
        const char *addr, unsigned int port, 
        int key_crypt, const char * key);

extern int radius_scheme_set_pri_acct(const char * name, 
        const char *addr, unsigned int port, 
        int key_crypt, const char * key);

extern int radius_scheme_set_sec_auth(const char * name, 
        const char *addr, unsigned int port, 
        int key_crypt, const char * key);

extern int radius_scheme_set_sec_acct(const char * name, 
        const char *addr, unsigned int port, 
        int key_crypt, const char * key);

struct radius_scheme_config_json {
    char    name[16 + 1];

    char    primary_auth_ip[16];
    int     primary_auth_port;
    char    primary_auth_key[64 + 1];
    int     primary_auth_key_crypt;

    char    primary_acct_ip[16];
    int     primary_acct_port;
    char    primary_acct_key[64 + 1];
    int     primary_acct_key_crypt;

    char    secondary_auth_ip[16];
    int     secondary_auth_port;
    char    secondary_auth_key[64 + 1];
    int     secondary_auth_key_crypt;

    char    secondary_acct_ip[16];
    int     secondary_acct_port;
    char    secondary_acct_key[64 + 1];
    int     secondary_acct_key_crypt;
};

struct radius_scheme_json {
    int num;
    struct radius_scheme_config_json config[16];
} ;
    
extern int radius_scheme_delete_force(const char * name);
extern int radius_scheme_get_all(struct radius_scheme_json *schemes);
#endif /* _AAA_SERVICES_H_ */
