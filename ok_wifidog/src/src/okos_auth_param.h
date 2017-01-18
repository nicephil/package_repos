#ifndef _OKOS_AUTH_PARAM_H_
#define _OKOS_AUTH_PARAM_H_

#if OK_PATCH



#define OKOS_AUTH_FAKE_TOKEN "TaiShangLaoJun-JiJiRuLvLing!"

#define OKOS_AUTH_INFO_VERSION 3
#define OKOS_AUTH_CNFM_VERSION 1

struct _t_client;

char * okos_http_insert_parameter(struct _t_client * );
int okos_http_parse_info(const char * , struct _t_client * );

#endif

#endif
