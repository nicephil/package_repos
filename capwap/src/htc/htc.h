#ifndef HTC_H
#define HTC_H

#define AH_MAX_STR_PARM_LEN 32
#define AH_MAX_STR_64_LEN 64


#define AH_CAPWAP_HTTP_TUNNEL_MAX_CONTENT_LEN (1024*1024)
#define AH_CAPWAP_HTTP_PROXY_AUTH_STR_PARA (2 * AH_MAX_STR_PARM_LEN + 2)
typedef struct {
	char *device;
	char host_name[AH_MAX_STR_PARM_LEN + 1];
	int host_port;
	char proxy_name[AH_MAX_STR_64_LEN + 1];
	int proxy_port;
	size_t proxy_buffer_size;
	int proxy_buffer_timeout;
	size_t content_length;
	int use_std;
	int use_daemon;
	int strict_content_length;
	int keep_alive;
	int max_connection_age;
	char proxy_authorization[AH_CAPWAP_HTTP_PROXY_AUTH_STR_PARA];
	char *user_agent;
} Htc_para;

int ah_capwap_http_tunnel_connect(Htc_para *arg);
int32_t ah_capwap_http_tunnel_send(char *buf, size_t length);
int32_t ah_capwap_http_tunnel_receive(char *buf, size_t length);
int ah_capwap_http_tunnel_listen(char *capwaprxpkt, uint32_t *pktlen);
int ah_capwap_http_tunnel_init_para();
int ah_capwap_http_tunnel_clean();

#endif

