/*********************************************************
AEROHIVE CONFIDENTIAL
Copyright [2006] - [2011] Aerohive Networks, Inc.
All Rights Reserved.
NOTICE: All information herein is and remains the property
of Aerohive Networks, Inc. and its suppliers, if any.
The intellectual and technical concepts contained herein
are proprietary to Aerohive Networks, Inc. and its
suppliers and may be covered by U.S. and foreign patents
and/or pending patent applications, and are protected by
trade secret and copyright law.
Disclosure, dissemination or reproduction of this
information or the intellectual or technical concepts
expressed by this information is prohibited unless prior
written permission is obtained from Aerohive Networks, Inc.
**********************************************************/
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ah_types.h"
#include "ah_syscall.h"
#include "ah_dbg_agent.h"

#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_dtls.h"
#include "ah_capwap_tcp.h"
#include "ah_lib.h"

#include "htc/htc.h"

static ah_capwap_tcp_handle_t ah_capwap_tcp_info;
/***************************************************************************
 *
 * Function:    ah_capwap_set_tcp_next_status
 *
 * Purpose:     set CAPWAP next connection TCP mode status
 *
 * Inputs:      tcp_enable: next connection TCP enable or disable
 *
 * Output:      void
 *
 * Returns:     0 is success, otherwise is failed
 *
 ***************************************************************************/
inline int ah_capwap_set_tcp_next_status(uchar tcp_enable)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_tcp_info.next_status = tcp_enable;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_tcp_next_status
 *
 * Purpose:   get CAPWAP next connection TCP mode status
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   CAPWAP next connection TCP mode status
 *
 ****************************************************************************/
inline int ah_capwap_get_tcp_next_status()
{
	uchar      next_status;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	next_status = ah_capwap_tcp_info.next_status;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return next_status;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_tcp_status
 *
 * Purpose:   get CAPWAP current connection TCP mode status
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   CAPWAP current connection TCP mode status
 *
 ****************************************************************************/
inline int ah_capwap_get_tcp_status()
{
	uchar      tcp_enable;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	tcp_enable = ah_capwap_tcp_info.tcp_enable;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return tcp_enable;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_tcp_status
 *
 * Purpose:   set CAPWAP current connection TCP mode status
 *
 * Inputs:    tcp_enable: current connection TCP enable or disable
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 ***************************************************************************/
inline int ah_capwap_set_tcp_status(uchar tcp_enable)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_tcp_info.tcp_enable = tcp_enable;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_tcp_http_proxy_info
 *
 * Purpose:   get CAPWAP http proxy info
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   CAPWAP next connection TCP mode status
 *
 ****************************************************************************/
inline int ah_capwap_get_tcp_http_proxy_info(char *name, int *port)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_strcpy(name, ah_capwap_para.proxy_name);
	*port = ah_capwap_para.proxy_port;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_tcp_http_proxy_info
 *
 * Purpose:   set CAPWAP http proxy info
 *
 * Inputs:    name: proxy name
 *                port: proxy port
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 ***************************************************************************/
inline int ah_capwap_set_tcp_http_proxy_info(char *name, int port)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_strcpy(ah_capwap_para.proxy_name, name);
	ah_capwap_para.proxy_port = port;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_tcp_http_proxy_auth_name_pswd
 *
 * Purpose:   get CAPWAP http proxy auth name and password
 *
 * Inputs:    void
 *
 * Output:    name: auth user name
 *            pswd: auth user password
 *
 * Returns:   CAPWAP next connection TCP mode status
 *
 ****************************************************************************/
inline int ah_capwap_get_tcp_http_proxy_auth_name_pswd(char *name, char *pswd)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_strcpy(name, ah_capwap_para.proxy_auth_name);
	ah_strcpy(pswd, ah_capwap_para.proxy_auth_pswd);
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_tcp_http_proxy_auth
 *
 * Purpose:   get CAPWAP http proxy auth info
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   CAPWAP next connection TCP mode status
 *
 ****************************************************************************/
inline int ah_capwap_get_tcp_http_proxy_auth(char *auth_info)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	if (ah_strlen(ah_capwap_para.proxy_auth_name) != 0) {
		ah_sprintf(auth_info, "%s:%s", ah_capwap_para.proxy_auth_name, ah_capwap_para.proxy_auth_pswd);
	} else {
		ah_strcpy(auth_info, "");
	}
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_tcp_http_proxy_auth
 *
 * Purpose:   set CAPWAP http proxy auth info
 *
 * Inputs:    name: proxy name
 *                pswd: proxy password
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 ***************************************************************************/
inline int ah_capwap_set_tcp_http_proxy_auth(char *name, char *pswd)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_strcpy(ah_capwap_para.proxy_auth_name, name);
	ah_strcpy(ah_capwap_para.proxy_auth_pswd, pswd);
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_tcp_http_proxy_content_length
 *
 * Purpose:   set CAPWAP http proxy content length
 *
 * Inputs:    length: content length
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 ***************************************************************************/
inline int ah_capwap_set_tcp_http_proxy_content_length(uint32_t length)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_para.proxy_content_len = length;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_tcp_http_proxy_content_length
 *
 * Purpose:   gset CAPWAP http proxy content length
 *
 * Inputs:    length: content length
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 ***************************************************************************/
inline int ah_capwap_get_tcp_http_proxy_content_length(uint32_t *length)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	if (ah_capwap_para.proxy_content_len == 0) {
		*length = AH_CAPWAP_HTTP_TUNNEL_MAX_CONTENT_LEN;
		ah_capwap_para.proxy_content_len = AH_CAPWAP_HTTP_TUNNEL_MAX_CONTENT_LEN;
	} else {
		*length = ah_capwap_para.proxy_content_len;
	}
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);
	ah_dbg_old(capwap_htc_basic, "HTTP proxy content length:%d\n", *length);

	return 0;
}

#ifdef AH_BONJOUR_GATEWAY_SUPPORT
/***************************************************************************
 *
 * Function:  ah_capwap_get_tcp_http_proxy_cfg_method
 *
 * Purpose:   get CAPWAP http proxy configuration by which method
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   CAPWAP http proxy configuration method
 *
 ****************************************************************************/
inline int ah_capwap_get_tcp_http_proxy_cfg_method()
{
	uchar      method;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	method = ah_capwap_para.proxy_cfg_method;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return method;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_tcp_http_proxy_cfg_method
 *
 * Purpose:   set CAPWAP http proxy configuration by which method
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   CAPWAP http proxy configuration method
 *
 ****************************************************************************/
inline int ah_capwap_set_tcp_http_proxy_cfg_method(char method)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	if (method || (!method && !ah_capwap_para.proxy_name[0] &&
				   !ah_capwap_para.proxy_port &&
				   !ah_capwap_para.proxy_auth_name[0] &&
				   !ah_capwap_para.proxy_auth_pswd[0])) {
		ah_capwap_para.proxy_cfg_method = method;
	}
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}



/***************************************************************************
 *
 * Function:  ah_capwap_request_http_proxy_cfg
 *
 * Purpose:   set CAPWAP http proxy configuration by which method
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   CAPWAP request http proxy configuration
 *
 ****************************************************************************/
inline int ah_capwap_request_http_proxy_cfg(void)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	if ((!ah_capwap_para.proxy_name[0] &&
		 !ah_capwap_para.proxy_port &&
		 !ah_capwap_para.proxy_auth_name[0] &&
		 !ah_capwap_para.proxy_auth_pswd[0])) {
		ah_capwap_monitor_bonjour_service();
	}
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_get_tcp_http_proxy_bonjour_service_type
 *
 * Purpose:   get CAPWAP http proxy bonjour service type
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   CAPWAP http proxy bonjour service type
 *
 ****************************************************************************/
inline int ah_capwap_get_tcp_http_proxy_bonjour_service_type()
{
	uchar      type;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	type = ah_capwap_para.bonjour_service_type;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return type;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_tcp_http_proxy_bonjour_service_type
 *
 * Purpose:   set CAPWAP http proxy bonjour service type
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:
 *
 ****************************************************************************/
inline int ah_capwap_set_tcp_http_proxy_bonjour_service_type(char type)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_para.bonjour_service_type = type;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}
#endif

/***************************************************************************
 *
 * Function:  ah_capwap_tcp_setup_connect
 *
 * Purpose:   handle CAPWAP TCP connection
 *
 * Inputs:    tcp_socket: tcp connection information
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 ****************************************************************************/
int ah_capwap_tcp_setup_connect(Htc_para *arg)
{
	return ah_capwap_http_tunnel_connect(arg);
}

/***************************************************************************
 *
 * Function:  ah_capwap_tcp_send
 *
 * Purpose:   send CAPWAP TCP connect packet
 *
 * Inputs:    buff: send packet buffer
 *            need_bytes: need send bytes
 *
 * Output:    void
 *
 * Returns:   send packet bytes
 *
 ****************************************************************************/
int32_t ah_capwap_tcp_send(char *buff, uint32_t need_bytes)
{
	return ah_capwap_http_tunnel_send(buff, need_bytes);
}

/***************************************************************************
 *
 * Function:  ah_capwap_client_tcp_listen
 *
 * Purpose:   listen the current TCP connect socket and wait for the packet
 *
 * Inputs:    void
 *
 * Output:    capwaprxpkt: receive packet buffer
 *            pktlen: receive packet length
 *
 * Returns:   0 is success, otherwise is failed
 *
 ****************************************************************************/
int ah_capwap_client_tcp_listen(char *capwaprxpkt, uint32_t *pktlen)
{

	return ah_capwap_http_tunnel_listen(capwaprxpkt, pktlen);
}

/***************************************************************************
 *
 * Function:  ah_capwap_tcp_init
 *
 * Purpose:   init CAPWAP TCP connection resource
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 ****************************************************************************/
int ah_capwap_tcp_init()
{
	/*check next connection status*/
	if (ah_capwap_get_tcp_next_status() != AH_CAPWAP_TCP_INIT) {
		ah_capwap_set_tcp_status(ah_capwap_get_tcp_next_status());
		ah_capwap_set_tcp_next_status(AH_CAPWAP_TCP_INIT);
	}
	/*if is initial status, change to disbale status*/
	if (ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_INIT) {
		ah_capwap_set_tcp_status(AH_CAPWAP_TCP_DISABLE);
	}
	/*release all the resource create in last TCP connection*/
	ah_capwap_http_tunnel_clean();

	if (ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_ENABLE_PREDEF_MODE) {
		ah_capwap_set_tcp_status(AH_CAPWAP_TCP_DISABLE);
	}

	return 0;
}


