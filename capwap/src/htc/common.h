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
#ifndef COMMON_H
#define COMMON_H
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#include "ah_lib.h"
#include "ah_dbg_agent.h"
#include "tunnel.h"
#include "../ah_capwap_func.h"

#define DEFAULT_HOST_PORT 8888
#define DEFAULT_CONTENT_LENGTH (100 * 1024) /* bytes */
#define DEFAULT_KEEP_ALIVE 5 /* seconds */
#define DEFAULT_MAX_CONNECTION_AGE 300 /* seconds */

extern int server_socket(struct in_addr addr, int port, int backlog);
extern int set_address(struct sockaddr_in *address,
					   const char *host, int port);
extern int open_device(char *device);
extern int handle_device_input(Tunnel *tunnel, int fd, int events);
extern int handle_tunnel_input(Tunnel *tunnel, int fd, int events);
extern void name_and_port(const char *nameport, char **name, int *port);
extern int atoi_with_postfix(const char *s_);
extern void log_sigpipe(int);
void dump_buf(FILE *f, unsigned char *buf, size_t len);

static inline ssize_t
read_all(int fd, void *buf, size_t len)
{
	ssize_t n, m, r;
	long flags;
	char *rbuf = buf;
	char stop = 0;

	flags = fcntl(fd, F_GETFL);
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		ah_err_old("%s: fcntl set O_NONBLOCK failed.", __func__);
	}

	r = len;
	for (n = 0; n < len; n += m) {
		m = read(fd, rbuf + n, len - n);
		if (m == 0) {
			r = 0;
			break;
		} else if (m == -1) {
			if (stop == 1) {
				r = 0;
				break;
			}
			ah_dbg_old(capwap_htc_info, "read all return error :%s\n", strerror(errno));
			ah_usleep(0, 50 * 1000);
			m = 0;
			stop = 1;
		}
		ah_capwap_increase_receive_bytes_counter((uint32_t) m);
	}

	if (fcntl(fd, F_SETFL, flags) < 0) {
		ah_err_old("%s: fcntl set flag failed.", __func__);
	}
	return r;
}

static inline ssize_t
write_all(int fd, void *data, size_t len)
{
	ssize_t n, m;
	char *wdata = data;
	long flags;
	int rc = 0;

	flags = fcntl(fd, F_GETFL);
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		ah_err_old("%s: fcntl set O_NONBLOCK failed, fd = %d.", __func__, fd);
	}

	for (n = 0; n < len; n += m) {
		m = write(fd, wdata + n, len - n);
		if (m == 0) {
			goto OUT;
		} else if (m == -1) {
			rc = -1;
			goto OUT;
		}
	}
	rc = len;

OUT:
	if (fcntl(fd, F_SETFL, flags) < 0) {
		ah_err_old("%s: fcntl set O_NONBLOCK failed, fd = %d.", __func__, fd);
	}
	return rc;
}

static inline int
do_connect(struct sockaddr_in *address)
{
#define AH_CAPWAP_TCP_CONNECT_TIMEOUT_INTERVAL (10)
	int fd;
	int      flags = 0;
	int rc = 0;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}

	/*set connection as noneblock mode*/
	flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		ah_err_old("%s: fcntl set O_NONBLOCK failed, fd = %d.", __func__, fd);
		rc = -1;
		goto OUT;
	}

	rc = connect(fd, (struct sockaddr *)address, sizeof(struct sockaddr_in));
	if (rc < 0) {
		if (EINPROGRESS != errno) {
			ah_dbg_old(capwap_htc_basic,  "CAPWAP_TCP:Can not setup a TCP connection, reason:%s", strerror(errno));
			rc = -1;
			goto OUT;
		}
		fd_set rset, wset;
		struct timeval tval;
		FD_ZERO(&rset);
		FD_SET(fd, &rset);
		wset = rset;
		tval.tv_sec = AH_CAPWAP_TCP_CONNECT_TIMEOUT_INTERVAL;
		tval.tv_usec = 0;
		rc = select(fd + 1, &rset, &wset, NULL, &tval);
		if (0 == rc) {
			/* timeout */
			ah_dbg_old(capwap_htc_basic, "CAPWAP_TCP:Setup TCP connection timed out");
			rc = -1;
			goto OUT;
		}
		if (FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
			int error = 0;
			socklen_t len = sizeof(error);
			rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
			if (rc < 0) {
				ah_dbg_old(capwap_htc_basic, "CAPWAP_TCP:Get TCP peer socket opt failed. reason:%s", strerror(errno));
				rc = -1;
				goto OUT;
			}
			if (error) {
				errno = error;
				ah_dbg_old(capwap_htc_basic, "CAPWAP_TCP:setup a TCP connection faild, reason:%s ",  strerror(errno));
				rc = -1;
				goto OUT;
			}
		} else {
			ah_dbg_old(capwap_htc_basic, "CAPWAP_TCP:setup a TCP connection error (reason:%s)", strerror(errno));
			rc = -1;
			goto OUT;
		}
	}

	//fcntl(fd, F_SETFL, flags);
	rc = 0;
	ah_dbg_old(capwap_htc_basic, "CAPWAP_TCP: setup a TCP connection successfully");
OUT:
	if (rc == -1) {
		close(fd);
		return rc;
	} else {
		return fd;
	}
}

static inline void
handle_input(const char *type, Tunnel *tunnel, int fd, int events,
			 int (*handler)(Tunnel *tunnel, int fd, int events),
			 int *closed)
{
	if (events) {
		ssize_t n;

		n = handler(tunnel, fd, events);
		if (n == 0 || (n == -1 && errno != EAGAIN)) {
			if (n == 0) {
				ah_dbg_old(capwap_htc_basic, "%s closed", type);
			} else {
				ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:%s read error: %s", type, strerror(errno));
			}
			*closed = TRUE;
		}
	}
}

#endif /* COMMON_H */
