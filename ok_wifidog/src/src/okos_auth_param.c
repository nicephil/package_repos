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

#include "gateway.h"

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
	debug(LOG_DEBUG, "^=== Start to transfer data to ASCII.");

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
    int i;
    for (i = 0; i < len; i++) hex[i] ^= 0xDA;
}

static unsigned char * okos_http_serial_local_info(const t_client *client, int *len)
{
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
    
	okos_http_ins_str(client->ssid->ssid, &pt);
	okos_http_ins_str(pconfig->domain_name, &pt);
    okos_http_ins_str(client->ssid->scheme, &pt);

	okos_mac_str2bin(client->ifx->bssid, pt);
    pt += 6;

    *len = pt - urltmp;

	debug(LOG_DEBUG, "^=== Serialized `local information` into INFO.");
    return urltmp;
}


#define pre_parse(left, size, element) {\
	size = sizeof(ptemp->element); \
	if (left < size) {\
		debug(LOG_ERR, "  =^!! Auth infor %s is too short.", #element);\
		return -1; }}
#define post_parse(left, pos, size) {\
	left -= size; pos += size;}

static int _okos_http_parse_info(const unsigned char *info, const int len, t_client *client)
{
    const unsigned char *pos = info;
    int left = len;
	t_auth_confirm_info *ptemp = NULL;
	int size;

	pre_parse(left, size, version);
	int ver = *((typeof(ptemp->version) *)pos);
	if (OKOS_AUTH_CNFM_VERSION != ver) {
		debug(LOG_ERR, "===^!! AUTH.version (%d) is wrong.", ver);
		return -2;
	}
	post_parse(left, pos, size);

	pre_parse(left, size, mac_num);
	int mac_num = *((typeof(ptemp->mac_num) *)pos);
	if (mac_num < 1 || mac_num > 2) {
		debug(LOG_ERR, "===^!! AUTH.mac_address_number (%d) is wrong.", mac_num);
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

	debug(LOG_DEBUG, "===^ Adjust user_name length from (%d) to buffer left %d",
            user_len, left);
	user_len = user_len <= left ? user_len : left;
	char * username = safe_malloc(user_len + 1);
	memcpy(username, pos, user_len);
	username[user_len] = '\0';
	okos_client_update_str_after_cmp(client->user_name, username);

	client->last_flushed = time(NULL);
    return 0;
}

char * okos_http_assemble_INFO(t_client *client)
{
	debug(LOG_DEBUG, "^= Start to assemble INFO variable.");
    int len = 0;
    unsigned char * urlBytes = okos_http_serial_local_info(client, &len);
    okos_http_encrypt_auth_info(urlBytes, len);
    char *info = okos_http_byte2hex(urlBytes, len);
    free(urlBytes);

	return info;
}

int okos_http_parse_AUTH(const char *auth_value, t_client *client)
{
	debug(LOG_DEBUG, "=^ Start to parse AUTH value.");
	int len = 0;
    unsigned char *param = okos_http_hex2byte(auth_value, &len);
	okos_http_encrypt_auth_info(param, len);
    int canntParse = _okos_http_parse_info(param, len, client);

    if (!canntParse) {
        debug(LOG_DEBUG, "=^ Client {mac:%s, user_name:%s, auth_mode:%d, remain_time:%d}"
                "parsed from AUTH variable.",
		        client->mac, client->user_name, client->auth_mode, client->remain_time);
    } else {
        debug(LOG_DEBUG, "=^!! parse AUTH value FAILED!");
    }
    free(param);
	return canntParse;
}

t_client *
okos_client_get_new(const char *ip)
{
    t_client *client = client_get_new();
    client->ip = safe_strdup(ip);
    return client;
}

sqlite3 *
okos_open_stainfo_db(void)
{
    sqlite3 *sta_info_db = NULL;
    int db_result = sqlite3_open(station_info_db_file, &sta_info_db);
    if (0 != db_result) {
        debug(LOG_ERR, "<sqlite>!! Open database %s failed because %s.",
                station_info_db_file, sqlite3_errmsg(sta_info_db));
        return NULL;
    } else {
        debug(LOG_DEBUG, "<sqlite>\t Open database %s successfully.", station_info_db_file);
        return sta_info_db;
    }
}

void
okos_close_stainfo_db(sqlite3 *db)
{
    sqlite3_close(db);
    debug(LOG_DEBUG, "<sqlite>\t Close database.");
}


static int
okos_show_station_info(
        void *data,
        int col_n,
        char **col_v,
        char **col_name
        )
{
    t_client *client = (t_client *)data;
    int i = 0;
    for (i = 0; i < col_n; i++) {
        debug(LOG_DEBUG, "<sqlite>\t\t key:%s, value:%s.",
                col_name[i], col_v[i] ? col_v[i] : "Nil");
        if (0 == strcasecmp(col_name[i], "IFNAME") && NULL != col_v[i]) {
            okos_client_set_strdup(client->if_name, col_v[i]);
        } else if (0 == strcasecmp(col_name[i], "MAC") && NULL != col_v[i]) {
            okos_client_set_strdup(client->mac, col_v[i]);
        } else {
            debug(LOG_DEBUG, "<sqlite>!! Got key[%s] UNREQUIRED.", col_name[i]);
        }
    }
    return 0;
}

/*-------------------------------------------------------------------
 * Acquire if_name [and mac address] through database query.
 *
 * INPUT: client->ip [client->mac]
 *
 * OUTPUT: client->if_name & [client->mac]
 *
 * RETURN:
 *      1) SQLite Query failed.
 *      2) Query return OK, but if_name is NULL.
 *      3) Query return OK, but maf is NULL.
 *      0) client's IP, MAC and IF_NAME are available. 
 * NOTES:
 *      1) If client->mac is available, Do NOT ruin it. It's the case
 *         of guest network authenticaion mode.
 *------------------------------------------------------------------*/
static int
okos_get_client_iface(t_client *client, sqlite3 *sta_info_db)
{
    /*---------------------------------------------------------------
     * STEP 3: Build up SQLite Query. 
     *         1) If MAC is available, Try to get 'if_name'.
     *         2) If MAC is NULL, Try to acquire 'if_name' & 'MAC'
     *            from IP address.
     *            This case may not success as always.
     * ------------------------------------------------------------*/
    char *sql = NULL;
    if (NULL != client->mac) { 
        safe_asprintf(&sql, "SELECT IFNAME from STAINFO " 
                "WHERE MAC = '%s';" 
                , client->mac);
    } else { 
        safe_asprintf(&sql, "SELECT MAC, IFNAME from STAINFO " 
                "WHERE IPADDR = '%s';" 
                , client->ip);
    }

    int failed = 0;
    char *err_msg = NULL;
    int rc = sqlite3_exec(sta_info_db, sql, okos_show_station_info, client, &err_msg);
    if (SQLITE_OK != rc) {
        debug(LOG_WARNING, "<sqlite>!! Query(%s) Failed for %s.",
                sql, err_msg);
        sqlite3_free(err_msg);
        failed = 1;
    } else {
        if (NULL == client->if_name) {
            failed = 2;
            debug(LOG_DEBUG, "<sqlite>!! Query(%s) success, but if_name is NULL)", sql);
        } else if (NULL == client->mac) {
            failed = 3;
            debug(LOG_DEBUG, "<sqlite>!! Query(%s) success, but mac is NULL)", sql);
        } else {
            debug(LOG_DEBUG, "<sqlite>\t Query(%s) success.", sql);
        }
    }

    free(sql);
    
    return failed;
}

/*-------------------------------------------------------------------
 * Try to file client data from:
 * 1) Local Information: MAC (arp table), IF_NAME (database);
 * 2) Configuration:
 *      1) String: SSID, Scheme
 *      2) Data Point: ifx & ssid
 *
 * INPUT: Client IP [MAC]
 *      1) httpd_callback_404: IP ONLY
 *      2) httpd_callback_auth: IP + MAC
 *      3) httpd_callback_allow: IP ONLY
 *      4) httpd_callback_qrcode: IP ONLY
 * OUTPUT: Either you got the items listed above, Or
 *         Nothing but client datastruct freed.
 * ----------------------------------------------------------------*/
void
okos_fill_local_info_by_stainfo(t_client **p_client, sqlite3 *sta_info_db)
{
    t_client *client = *p_client;
    if (NULL == client->mac) {
        client->mac = arp_get(client->ip);
    }

    int failed = okos_get_client_iface(client, sta_info_db);
    if (!failed) { /* client's IP, MAC & if_name is ready. */
        client->ifx = okos_conf_get_ifx_by_name(client->if_name);
        if (NULL != client->ifx) {
            client->ssid = client->ifx->ssid;
            if (NULL != client->ssid) {
                debug(LOG_DEBUG, "<client_info>\t Found record:"
                        "{%s, %s, %s, %s, scheme:%s}",
                        client->ip, client->mac, client->if_name,
                        client->ssid->ssid, client->ssid->scheme);

                return;
            } else {
                debug(LOG_DEBUG, "<client_info>!! 'ssid' is imcompleted.");
            }
        } else {
            debug(LOG_DEBUG, "<client_info>!! 'ifx' is imcompleted.");
        }
    }

    client_free_node(client);
    *p_client = NULL;

    return;
}

/*---------------------------------------------------------
 * Client Fields Filled:
 *      LAST_FLUSHED
 *      REMAIN_TIME
 *      USER_NAME  -- Just fake a NULL string.
 *-------------------------------------------------------*/
void
okos_client_update_allow_time(t_client **p_client, const char *time_value)
{
    t_client *client = *p_client;
    /*---------------------------------------------------------------
     * For all the cases below, they are invalid ALLOW,
     * Just Drop it.
     * ------------------------------------------------------------*/
    if (NULL == time_value) {
        debug(LOG_DEBUG, "<client_info>!! TIME is NULL for client{%s,%s,%s}",
                client->ip, client->mac, client->if_name);
        client_free_node(client);
        *p_client = NULL;
        return;
    }
    int sec = 0;
    if (1 != sscanf(time_value, "%d", &sec)) {
        debug(LOG_DEBUG, "<client_info>!! TIME is %s(str) for client{%s,%s,%s}",
                time_value, client->ip, client->mac, client->if_name);
        client_free_node(client);
        *p_client = NULL;
        return;
    }
    if (0 >= sec || sec > 300) {
        debug(LOG_DEBUG, "<client_info>!! TIME is %d(int) for client{%s,%s,%s}",
                sec, client->ip, client->mac, client->if_name);
        client_free_node(client);
        *p_client = NULL;
        return;
    }

    client->remain_time = sec;
    client->last_flushed = time(NULL);

    debug(LOG_DEBUG, "<client_info>\t\t Created a VALIDATION client"
            "{%s, %s, %s, remain_time=%ld }",
            client->ip, client->mac, client->if_name, client->remain_time);
    return;
}


static int okos_update_stainfo_callback(void *data, int col_n, char **_v, char **_k)
{
    int i;
    for (i = 0; i < col_n; i++) {
        debug(LOG_DEBUG, "<sqlite>\t %s", data ? data : "");
        debug(LOG_DEBUG, "<sqlite>\t\t key:%s; value:%s", _k[i], _v[i] ? _v[i]: "Nil");
    }
    return 0;
}

void okos_update_station_info(sqlite3 *sta_info_db, t_client *client)
{
    /* Create merged SQL statement */
    char *sql = NULL;
    safe_asprintf(&sql, "UPDATE STAINFO set " \
            "PORTAL_SCHEME='%s', PORTAL_MODE='%d'," \
            "PORTAL_USER='%s', IPADDR='%s' " \
            "WHERE MAC='%s';" \
            /* "SELECT * from STAINFO where MAC='%s';" \ */
            ,
            client->ssid->scheme, client->auth_mode,
            client->user_name, client->ip,
            client->mac,
            client->mac
            );
    debug(LOG_DEBUG, "<sqlite>\t '%s':", sql);

    /* Execute SQL statement */
    char *err_msg = NULL;
    int rc = sqlite3_exec(sta_info_db, sql, okos_update_stainfo_callback, (void*)NULL, &err_msg);
    if (SQLITE_OK != rc) {
        debug(LOG_DEBUG, "<sqlite>!! Update '%s' failed because %s", sql, err_msg);
        sqlite3_free(err_msg);
    }else{
        debug(LOG_DEBUG, "<sqlite>\t Update '%s' successfully.", sql);
    }

    free(sql);
}


char *
okos_client_get_ssid(const t_client *client)
{
    return client->ssid->ssid;
}


void
okos_client_set_expired(t_client *client)
{
    client->remain_time = 0;
    client->last_flushed = time(NULL);
}

#endif
