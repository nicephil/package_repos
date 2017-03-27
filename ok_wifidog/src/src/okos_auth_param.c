#if OK_PATCH
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>


#include "okos_auth_param.h"
#include "debug.h"
#include "firewall.h"
#include "conf.h"
#include "safe.h"
#include "client_list.h"

typedef struct s_http_auth_info_pri {
    /* Pravite Part: */
#define OKOS_BRIF_NAME_LEN 64
#define OKOS_UNKNOWN_BR "br-OKOS_UNKNOWN_BRIDGE_INTERFACE"
    char br_interface[OKOS_BRIF_NAME_LEN+1];
}t_http_auth_info_pri;

#define OKOS_URLPARA_SSID_MLEN      255
#define OKOS_URLPARA_DOMAIN_MLEN    255
#define OKOS_URLPARA_SCHEME_MLEN    255
typedef struct s_http_auth_info {
    unsigned char version; //version == 3

    unsigned char device_mac[6];
    
    unsigned char client_mac[6];
    unsigned int  client_ip;

    unsigned char ssid_len;
    char ssid[OKOS_URLPARA_SSID_MLEN];
    unsigned char domain_len;
    char domain[OKOS_URLPARA_DOMAIN_MLEN];
    unsigned char scheme_len;
    char scheme[OKOS_URLPARA_SCHEME_MLEN];

    unsigned char bssid[6];
}t_http_auth_info;


#define OKOS_URLPARA_USRNM_MLEN 64
typedef struct s_auth_confirm_info {
    unsigned char version;
    unsigned char mac_num;
    unsigned char mac1[6];
    unsigned char mac2[6];
    unsigned int auth_mode;
    unsigned int remain_time;
    unsigned char user_len;
    char user[OKOS_URLPARA_USRNM_MLEN+1];
}t_auth_confirm_info;



static int okos_mac_bin2str(const unsigned char *mac, char **macstr)
{
    if (NULL == mac)
        return -1;
    safe_asprintf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return 0;
}

static int okos_mac_str2bin(const char *macstr, unsigned char *mac)
{
    if (NULL == macstr || 17 != strlen(macstr))
        goto bad;
    unsigned int tmp[6];
    if (6 != sscanf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x", &tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]))
        goto bad;
    
    int i;
    for (i = 0; i < 6; i++)
        mac[i] = tmp[i] & 0xFF;

    return 0;

bad:
    memset(mac, 0, 6);
    return -1;
}

static inline void okos_http_ins_str(const char *desc, unsigned char **pt)
{
	unsigned char len = strlen(desc);
    **pt = len;
	*pt += 1;
    memcpy(*pt, desc, len);
    *pt += len;
}


static unsigned char * okos_http_serial_auth_info(const t_client *client, int *len)
{
//    okos_http_simulate_client_info(client, &info);
	debug(LOG_DEBUG, ".... serialize the local information into buffer.");

    unsigned char * urltmp = safe_malloc(sizeof(t_http_auth_info));
    unsigned char * pt = urltmp;
	s_config *pconfig = config_get_config();

    *pt++ = OKOS_AUTH_INFO_VERSION;
	okos_mac_str2bin(pconfig->device_id, pt);
	pt += 6;
	okos_mac_str2bin(client->mac, pt);
    pt += 6;
    unsigned long client_ip = htonl(inet_addr(client->ip));
    memcpy(pt, (char *)(&(client_ip)), sizeof(client_ip));
    pt += sizeof(client_ip);
    
	okos_http_ins_str(client->ssid, &pt);
	okos_http_ins_str(pconfig->domain_name, &pt);
    okos_http_ins_str(client->ssid_conf->scheme_name, &pt);

	okos_mac_str2bin(client->ifx->bssid, pt);
    pt += 6;

    *len = pt - urltmp;

    return urltmp;
}

static unsigned char * okos_http_hex2byte(const char *hex, int *len)
{
    int num = strlen(hex)/2;
    unsigned char *bytes = safe_malloc(num);

    int i;
    for (i = 0; i < num; i++) {
        int j;
        unsigned char tmp[2];
        for (j = 0; j < 2; j++) {
            char next = hex[i*2+j];
            if (next >= '0' && next <= '9'){
                tmp[j] = next - '0';
            }else if (next >= 'a' && next <= 'z'){
                tmp[j] = next - 'a' + 10;
            }else if (next >= 'A' && next <= 'Z'){
                tmp[j] = next - 'A' + 10;
            }else{
				break;
            }
        }
		if (j == 2)
			bytes[i] = ((tmp[0]&0xF) << 4) | (tmp[1]&0xF);
		else
			break;
    }

    *len = i;
    return bytes;
}

static char * okos_http_byte2hex(const unsigned char *bytes, const int len)
{
	debug(LOG_DEBUG, ".... start to transfer data to ascii.");

    char *hex = safe_malloc(len*2+1);
    char alph[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    int i,j;
    for (j = 0, i = 0; i < len; i++){
        hex[j++] = alph[bytes[i] >> 4 & 0xF];
        hex[j++] = alph[bytes[i] & 0xF];
    }
    hex[j] = '\0';
    return hex;
}

static inline void okos_http_encrypt_auth_info(unsigned char *hex, const int len)
{
	debug(LOG_DEBUG, ".... start to encrypt the auth information.");
    int i;
    for (i = 0; i < len; i++) hex[i] ^= 0xDA;
}

static int _okos_http_parse_info(const unsigned char *info, const int len, t_client *client)
{
    const unsigned char *pos = info;
    int left = len;
	t_auth_confirm_info *ptemp = NULL;
	int size;

#define pre_parse(left, size, element) {\
	size = sizeof(ptemp->element); \
	if (left < size) {\
		debug(LOG_ERR, "Auth infor %s is too short.", #element);\
		return -1; }}
#define post_parse(left, pos, size) {\
	left -= size; pos += size;}

	pre_parse(left, size, version);
	int ver = *((typeof(ptemp->version) *)pos);
	if (OKOS_AUTH_CNFM_VERSION != ver) {
		debug(LOG_ERR, "Auth confirm info version (%d) is wrong.", ver);
		return -2;
	}
	post_parse(left, pos, size);

	pre_parse(left, size, mac_num);
	int mac_num = *((typeof(ptemp->mac_num) *)pos);
	if (mac_num < 1 || mac_num > 2) {
		debug(LOG_ERR, "Mac address number (%d) is wrong.", mac_num);
		return -1;
	}
	post_parse(left, pos, size);

	pre_parse(left, size, mac1);
	char *mac;
	okos_mac_bin2str(pos, &mac);
	okos_client_update_str_after_casecmp(client->mac, mac);
	post_parse(left, pos, size);

	if (2 == mac_num) {
		pre_parse(left, size, mac2);
		post_parse(left, pos, size);
	}

	pre_parse(left, size, auth_mode);
	client->auth_mode = ntohl(*((typeof(ptemp->auth_mode) *)pos));
	post_parse(left, pos, size);

	pre_parse(left, size, remain_time);
	client->remain_time = ntohl(*((typeof(ptemp->remain_time) *)pos));
	post_parse(left, pos, size);

	pre_parse(left, size, user_len);
	typeof(ptemp->user_len) user_len = *((typeof(ptemp->user_len) *)pos);
	post_parse(left, pos, size);

	debug(LOG_DEBUG, ".... Compare&Adjust the user name length from msg content (%d) to buffer left %d", user_len, left);
	user_len = user_len <= left ? user_len : left;
	char * username = safe_malloc(user_len + 1);
	memcpy(username, pos, user_len);
	username[user_len] = '\0';
	okos_client_update_str_after_cmp(client->user_name, username);

	client->last_flushed = time(NULL);
	debug(LOG_DEBUG, ".... Auth confirm information parse successful for client {mac:%s, auth_mode:%d, remain_time:%d, user_name:%s}", client->mac, client->auth_mode, client->remain_time, client->user_name);
    return 0;
}

char * okos_http_insert_parameter(t_client *client)
{
	debug(LOG_DEBUG, ".. start to insert parameter to auth info ..");
    int len = 0;
    unsigned char * urlBytes = okos_http_serial_auth_info(client, &len);
    okos_http_encrypt_auth_info(urlBytes, len);
    char *info = okos_http_byte2hex(urlBytes, len);
    free(urlBytes);

	return info;
}

int okos_http_parse_info(const char *auth_value, t_client *client)
{
	debug(LOG_DEBUG, ".. start to parse auth value.");
	int len = 0;
    unsigned char *param = okos_http_hex2byte(auth_value, &len);
	okos_http_encrypt_auth_info(param, len);
    int canntParse = _okos_http_parse_info(param, len, client);

    if (!canntParse) {
        debug(LOG_DEBUG, ".. Client {mac:%s, user_name:%s, auth_mode:%d, remain_time:%d} got authed.",
		        client->user_name, client->mac, client->auth_mode, client->remain_time);
    }
	debug(LOG_DEBUG, ".. parse auth value %s.", canntParse ? "failed" : "successfully");
    free(param);
	return canntParse;
}


#endif
