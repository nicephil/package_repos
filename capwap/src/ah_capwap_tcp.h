#ifndef AH_CAPWAP_TCP_H
#define AH_CAPWAP_TCP_H

#include "htc/htc.h"

typedef struct {
	uchar      tcp_enable;   /*CAPWAP support TCP enable flag*/
	uchar      next_status;  /*CAPWAP next transfer mode status*/
} ah_capwap_tcp_handle_t;

typedef enum {
	AH_CAPWAP_TCP_INIT = 0,
	AH_CAPWAP_TCP_DISABLE,
	AH_CAPWAP_TCP_ENABLE,
	AH_CAPWAP_TCP_ENABLE_PREDEF_MODE,
} ah_capwap_tcp_enable_mode_t;

inline int ah_capwap_set_tcp_status(uchar tcp_enable);
inline int ah_capwap_get_tcp_status();
inline int ah_capwap_set_tcp_next_status(uchar tcp_enable);
inline int ah_capwap_get_tcp_next_status();
int ah_capwap_tcp_setup_connect(Htc_para *arg);
int ah_capwap_client_tcp_listen(char *capwaprxpkt, uint32_t *pktlen);
int32_t ah_capwap_tcp_send(char *buff, uint32_t need_bytes);
int ah_capwap_tcp_init();
inline int ah_capwap_get_tcp_http_proxy_info(char *name, int *port);
inline int ah_capwap_set_tcp_http_proxy_info(char *name, int port);
inline int ah_capwap_get_tcp_http_proxy_auth(char *auth_info);
inline int ah_capwap_set_tcp_http_proxy_auth(char *name, char *pswd);
inline int ah_capwap_set_tcp_http_proxy_content_length(uint32_t length);
inline int ah_capwap_get_tcp_http_proxy_content_length(uint32_t *length);
inline int ah_capwap_get_tcp_http_proxy_auth_name_pswd(char *name, char *pswd);
#endif

