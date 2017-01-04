#ifndef __DNSSET_SERVICES_H_
#define __DNSSET_SERVICES_H_

#define DNS_SETNAME_MAXLEN 32
#define DNS_KEY_MAXLEN 32
#define NAME_MAXLEN 64

typedef struct key_list 
{
    struct key_list *next;
    
    char key[DNS_KEY_MAXLEN + 1];
    char kid;
} KEY_S;

typedef struct dns_set_t
{
    struct dns_set_t *next;
    char name[DNS_SETNAME_MAXLEN + 1];

    char enable;
    char refcount;
    int keycount;
    KEY_S *keylist;
} DNSSET_S;

#define DNSSET_MAX_COUNT 10
#define DNSKEY_MAX_COUNT 10
#define DNSSET_CFG_PACKAGE "dns_set"
extern DNSSET_S * dnsset_cfg_getall(void);
extern int dnsset_destroy(char *name);
extern void dnsset_cfg_free(DNSSET_S *dns_set);
extern int dnsset_create(char *name);
extern int dnsset_disable(char *name);

#endif /* __DNSSET_SERVICES_H_ */
