#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ah_types.h"
#include "ah_syscall.h"

#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_dtls.h"
#include "ah_capwap_tcp.h"

#include "base64.h"
#include "http.h"
#include "tunnel.h"
#include "common.h"
#include "ah_flow_msg.h"
#include "ah_tpa_api.h"

static Tunnel *ah_capwap_tunnel = NULL;

int ah_capwap_http_tunnel_init_para(Htc_para *arg)
{
#define AH_CAPWAP_HTTP_TUNNEL_KEEP_ALIVE_TIME 5
	arg->device = NULL;
	ah_sprintf(arg->host_name, "%i", htonl(ah_capwap_info.acip));
	arg->host_port = ah_capwap_para.capwap_port;
	ah_capwap_get_tcp_http_proxy_info(arg->proxy_name, &arg->proxy_port);
	arg->proxy_buffer_size = 0;
	arg->proxy_buffer_timeout = -1;
	ah_capwap_get_tcp_http_proxy_content_length((uint32_t *)&arg->content_length);
	arg->use_std = FALSE;
	arg->use_daemon = TRUE;
	arg->strict_content_length = FALSE;
	arg->keep_alive = AH_CAPWAP_HTTP_TUNNEL_KEEP_ALIVE_TIME;
	arg->max_connection_age = 300;
	ah_capwap_get_tcp_http_proxy_auth(arg->proxy_authorization);
	arg->user_agent = NULL;

	return 0;
}

int32_t ah_capwap_http_tunnel_receive(char *buf, size_t length)
{
	return tunnel_read(ah_capwap_tunnel, buf, length);
}

int ah_capwap_http_tunnel_listen(char *capwaprxpkt, uint32_t *pktlen)
{
#define AH_CAPWAP_SELECT_TIMER 20000
	int      len = 0;
	uint      dtls_len = 0;
	fd_set fdR;
	uint      max_socket = 0;
	int      rc = 0;
	struct sockaddr_in dtls_pkt;
	struct timeval capwapsel = {0, AH_CAPWAP_SELECT_TIMER};
	int      socket = -1;

	dtls_len = sizeof(dtls_pkt);
	/*waiting for response packet, if have event, handle it at once*/
	if (ah_capwap_para.event != AH_CAPWAP_EVENT_WAIT) {
		ah_capwap_interrupt_listen();
	}
	ah_dbg_old(capwap_basic, "CAPWAP: cur_status:%s, cur_event:%s, timer to fire:%d", ah_capwap_get_state_string(ah_capwap_info.state),
			   ah_capwap_get_event_string(ah_capwap_info.event), ah_capwap_get_time2fire());
	if (capwap_basic) {
		ah_log_old(AH_LOG_INFO, "CAPWAP: cur_status:%s, cur_event:%s, timer to fire:%d", ah_capwap_get_state_string(ah_capwap_info.state),
				   ah_capwap_get_event_string(ah_capwap_info.event), ah_capwap_get_time2fire());
	}
	while (ah_capwap_get_listen_state()  && ah_capwap_para.enable == AH_CAPWAP_ENABLE) {
		socket = tunnel_pollin_fd(ah_capwap_tunnel);
		if (socket == -1) {
			ah_sleep(1);
			if (tunnel_in_connect(ah_capwap_tunnel) <= 0) {
				ah_dbg_old(capwap_htc_basic, "In connection down, need reset IN connect.");
			} else {
				socket = tunnel_pollin_fd(ah_capwap_tunnel);
				ah_dbg_old(capwap_htc_basic, "Reset IN connection . IN fd=%d\n", socket);
			}
		}
		capwapsel.tv_usec = AH_CAPWAP_SELECT_TIMER;
		FD_ZERO(&fdR);
		if (socket != -1) {
			FD_SET(socket, &fdR);
		}
		if (ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ] != AH_CAPWAP_DTLS_SOCKET_UNAVLIB
				&& ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_WRITE] != AH_CAPWAP_DTLS_SOCKET_UNAVLIB) {
			FD_SET(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], &fdR);
		}
		/*set the max select socket number*/
		if (socket > ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ]) {
			max_socket = socket + 1;
		} else {
			max_socket = ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ] + 1;
		}
		switch (select(max_socket, &fdR, NULL, NULL, &capwapsel)) {
			case -1:
				if (errno == EINTR) {
					continue;
				}
				ah_dbg_old(capwap_htc_info, "CAPWAP call select function errno:%d reason:%s!\n", errno, strerror(errno));
				continue;
			case 0:
				/*select time out*/
				continue;
			default:
				if (socket != -1 && FD_ISSET(socket, &fdR)) {
					len = ah_capwap_http_tunnel_receive(capwaprxpkt, AH_CAPWAP_BUF_LEN);
					ah_dbg_old(capwap_htc_info, "Receive the tcp payload len %d bytes", len);
					if (len <= 0) {
						continue;
					}
					*pktlen = len;

					/*check packet is SSL packet or not*/
					rc = ah_capwap_dtls_pkt_type(capwaprxpkt, len);
					if (rc == AH_CAPWAP_DTLS_PKT) {
						/*will read from SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], send DTLS packet in function
						  ah_capwap_dtls_pkt_type()*/
						continue ;
					} else if (rc == AH_CAPWAP_ERROR_PKT) {
						/*drop it*/
						continue;
					}
					/*analyse the packet*/
					if (ah_capwap_analysepacket(capwaprxpkt, len) == -1) {
						ah_dbg_old(capwap_htc_info, "receive an error format pakcet!\n");
						continue;
					}
					if (capwap_packet) {
						ah_dbg_old(capwap_packet, "CAPWAP client receive packet len %d.\n", len);
						ah_hexdump((uchar *)capwaprxpkt, len);
					}

					return 0;
				}
				/*capwap and ssl socket, local socket*/
				if ((ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ] != AH_CAPWAP_DTLS_SOCKET_UNAVLIB)
						&& FD_ISSET(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], &fdR)) {
					if ((len = recvfrom(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ],
										(char *)capwaprxpkt, AH_CAPWAP_BUF_LEN, 0, (struct sockaddr *)&dtls_pkt, &dtls_len)) <= 0) {
						ah_dbg_old(capwap_ssl, "SSL socket receive from failed. reason:%s\n", strerror(errno));
						continue;
					}
					ah_dbg_old(capwap_ssl, "SSL socket receive from %i, pkt len:%d\n", ntohl(dtls_pkt.sin_addr.s_addr), len);
					if (capwap_packet) {
						ah_hexdump((uchar *)capwaprxpkt, len);
					}
					/*add the capwap header and send the SSL packet, go on waitting for*/
					ah_capwap_dtls_snd_pkt(capwaprxpkt, len);

					continue;
				}
		}
	}
	return 0;
}

int32_t ah_capwap_http_tunnel_send(char *buff, size_t need_bytes)
{
	return tunnel_write(ah_capwap_tunnel, buff, need_bytes);
}

int ah_capwap_http_tunnel_clean()
{
	if (ah_capwap_tunnel) {
		tunnel_close(ah_capwap_tunnel);
		free(ah_capwap_tunnel);
		ah_capwap_tunnel = NULL;
	}

	return 0;
}

int ah_capwap_http_tunnel_connect(Htc_para *arg)
{

	int rc = -1;

	ah_dbg_old(capwap_htc_basic, "creating a new tunnel");
	/*create a new TCP tunnel*/
	ah_capwap_tunnel = tunnel_new_client(arg->host_name, arg->host_port,
										 arg->proxy_name, arg->proxy_port,
										 arg->content_length);
	if (ah_capwap_tunnel == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP: couldn't create tunnel");
		goto OUT;
	}
	if (tunnel_setopt(ah_capwap_tunnel, "strict_content_length", &arg->strict_content_length) == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP: tunnel_setopt strict_content_length error: %s", strerror(errno));
		goto OUT;
	}
	if (tunnel_setopt(ah_capwap_tunnel, "keep_alive",  &arg->keep_alive) == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP: tunnel_setopt keep_alive error: %s", strerror(errno));
		goto OUT;
	}
	if (tunnel_setopt(ah_capwap_tunnel, "max_connection_age",  &arg->max_connection_age) == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP: tunnel_setopt max_connection_age error: %s", strerror(errno));
		goto OUT;
	}
	if (strlen(arg->proxy_authorization) != 0) {
		ssize_t len;
		char *auth = NULL;

		ah_dbg_old(capwap_htc_basic, "Generate the authentication :%s", arg->proxy_authorization);
		len = encode_base64(arg->proxy_authorization, strlen(arg->proxy_authorization), &auth);
		if (len == -1) {
			ah_log_old(AH_LOG_ERR, "encode_base64 error: %s", strerror(errno));
			if (auth != NULL) {
				free(auth);
			}
			goto OUT;
		} else {
			char *str = malloc(len + 7);

			if (str == NULL) {
				ah_log_old(AH_LOG_ERR, "out of memory when encoding authorization string");
				free(auth);
				goto OUT;
			}
			strcpy(str, "Basic ");
			strcat(str, auth);
			free(auth);
			if (tunnel_setopt(ah_capwap_tunnel, "proxy_authorization", str) == -1) {
				ah_log_old(AH_LOG_ERR, "CAPWAP_TCP: tunnel_setopt proxy_authorization error: %s", strerror(errno));
				free(str);
				goto OUT;
			}
			free(str);
		}
	}
	/*"  -U, --user-agent STRING        specify User-Agent value in HTTP requests\n"*/
	if (arg->user_agent != NULL) {
		if (tunnel_setopt(ah_capwap_tunnel, "user_agent", arg->user_agent) == -1) {
			ah_log_old(AH_LOG_ERR, "CAPWAP_TCP: tunnel_setopt user_agent error: %s", strerror(errno));
		}
	}
	/*ready do connect with proxy*/
	ah_dbg_old(capwap_htc_basic, "Ready connect with remote HTTP tunnel server\n");
	/*register destnation port to FE*/
	if (arg->proxy_port > 0) {
		ah_dbg_old(capwap_htc_basic,  "register proxy port :%d\n", arg->proxy_port);
		ah_tpa_fe_register_to_self_pkt_port(IPPROTO_TCP, arg->proxy_port, AH_TO_SELF_SRC_CHECK, "CAPWAP proxy port");
	}
	if (tunnel_connect(ah_capwap_tunnel) == -1) {
		ah_log_old(AH_LOG_WARNING, "CAPWAP:couldn't open tunnel: %s", strerror(errno));
		goto OUT;
	}
	ah_dbg_old(capwap_htc_basic, "Connect with remote HTTP tunnel server done\n");
	if (ah_strlen(arg->proxy_name) != 0) {
		ah_log_old(AH_LOG_NOTICE, "CAPWAP_TCP: connected to %s:%d via %s:%d", arg->host_name, arg->host_port, arg->proxy_name, arg->proxy_port);
	} else {
		ah_log_old(AH_LOG_NOTICE, "CAPWAP_TCP: connected to %s:%d", arg->host_name, arg->host_port);
	}

	rc = 0;
OUT:
	if (rc == -1) {
		ah_capwap_http_tunnel_clean();
	}
	return rc;
}

