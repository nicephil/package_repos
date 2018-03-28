#ifndef _OKOS_AUTH_PARAM_H_
#define _OKOS_AUTH_PARAM_H_


#define OKOS_WFD_MAX_STR_LEN 255

#define OKOS_AUTH_FAKE_TOKEN "TaiShangLaoJun-JiJiRuLvLing!"

#define OKOS_AUTH_INFO_VERSION 3
#define OKOS_AUTH_CNFM_VERSION 1

struct _t_client;

char * okos_http_assemble_INFO(struct _t_client *);
int okos_http_parse_AUTH(const char * , struct _t_client * );

#include <sqlite3.h>

struct _t_client * okos_client_get_new(const char *);
void okos_client_update_allow_time(struct _t_client **, const char *);
void okos_fill_local_info_by_stainfo(struct _t_client **, sqlite3 *);
void okos_update_station_info(sqlite3 *, struct _t_client *);
void okos_update_station_info_v1(sqlite3 *, struct _t_client *);
void okos_update_portal_status_info(sqlite3 *, struct _t_client *);

sqlite3 * okos_open_stainfo_db(void);
void okos_close_stainfo_db(sqlite3 *);


char * okos_client_get_ssid(const struct _t_client *);
void okos_client_set_expired(struct _t_client *);

#define okos_client_set_str(element, src) do { \
    if (element) free(element); \
    element = (src); \
    src = NULL; \
} while (0)

#define okos_client_set_strdup(element, src) do { \
    if (element) free(element); \
    element = safe_strdup(src); \
} while (0)


#define okos_client_update_str_after_cmp(element, src) do { \
    if (!element) {\
        element = src; \
    } else if (0 != strcmp(element, src)) { \
        free(element); \
        element = src; \
    } else { \
        free(src); \
    } \
    src = NULL; \
} while (0)

#define okos_client_update_str_after_casecmp(element, src) do { \
    if (!element) {\
        element = src; \
    } else if (0 != strcasecmp(element, src)) {\
        free(element); \
        element = src; \
    } else { \
        free(src); \
    } \
    src = NULL; \
} while (0)

#define okos_client_update_strdup_after_cmp(element, src) do { \
    if (!element) {\
        element = safe_strdup(src); \
    } else if (0 != strcmp(element, src)) { \
        free(element); \
        element = safe_strdup(src); \
    } \
} while (0)

#define okos_client_update_strdup_after_casecmp(element, src) do { \
    if (!element) {\
        element = safe_strdup(src); \
    } else if (0 != strcasecmp(element, src)) { \
        free(element); \
        element = safe_strdup(src); \
    } \
} while (0)

#endif
