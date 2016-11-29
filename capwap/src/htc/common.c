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
#include <time.h>
#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <termios.h>
#include <sys/poll.h>

#include "ah_lib.h"
#include "ah_dbg_agent.h"
#include "tunnel.h"
#include "common.h"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

	int
server_socket (struct in_addr addr, int port, int backlog)
{
	struct sockaddr_in address;
	int i, s;

	s = socket (PF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		return -1;

	i = 1;
	if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (void *)&i, sizeof i) == -1)
	{
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:server_socket: setsockopt SO_REUSEADDR: %s",
				strerror (errno));
	}

	memset (&address, '\0', sizeof address);
	address.sin_family = PF_INET;
	address.sin_port = htons ((short)port);
	address.sin_addr = addr;

	if (bind (s, (struct sockaddr *)&address, sizeof (address)) == -1)
	{
		close (s);
		return -1;
	}
#if 0
	/*转为被动等待连接*/
	if (listen (s, (unsigned)backlog) == -1)
	{
		close (s);
		return -1;
	} 
#endif
	return s;
}

	int
set_address (struct sockaddr_in *address, const char *host, int port)
{
	memset (address, '\0', sizeof *address);
	address->sin_family = PF_INET;
	address->sin_port = htons ((u_short)port);
	address->sin_addr.s_addr = inet_addr (host);

	/*INADDR_NONE 为广播地址*/
	if (address->sin_addr.s_addr == INADDR_NONE)
	{
		struct hostent *ent;
		unsigned int ip;

		ah_dbg_old(capwap_htc_info, "set_address: gethostbyname (\"%s\")", host);
		ent = gethostbyname (host);
		ah_dbg_old(capwap_htc_info, "set_address: ent = %p", ent);
		if (ent == 0)
			return -1;

		memcpy(&address->sin_addr.s_addr, ent->h_addr, (unsigned)ent->h_length);
		ip = ntohl (address->sin_addr.s_addr);
		ah_dbg_old(capwap_htc_info, "set_address: host = %d.%d.%d.%d",
				ntohl (ip) >> 24,
				(ntohl (ip) >> 16) & 0xff,
				(ntohl (ip) >>  8) & 0xff,
				ntohl (ip)        & 0xff);
	}

	return 0;
}

	int
open_device (char *device)
{
	struct termios t;
	int fd;

	fd = open (device, O_RDWR | O_NONBLOCK);
	if (fd == -1)
		return -1;

	if (tcgetattr (fd, &t) == -1)
	{
		if (errno == ENOTTY || errno == EINVAL)
			return fd;
		else {
			close(fd);
			return -1;
		}
	}
	t.c_iflag = 0;
	t.c_oflag = 0;
	t.c_lflag = 0;
	if (tcsetattr (fd, TCSANOW, &t) == -1){
		close(fd);
		return -1;
	}

	return fd;
}

	void
dump_buf (FILE *f, unsigned char *buf, size_t len)
{
	if (capwap_htc_detail){
		ah_hexdump(buf, len);
	}
}

	int
handle_device_input (Tunnel *tunnel, int fd, int events)
{
	unsigned char buf[10240];
	ssize_t n, m;

	if (events & POLLIN)
	{
		n = read (fd, buf, sizeof buf);
		if (n == 0 || n == -1)
		{
			if (n == -1 && errno != EAGAIN)
				ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: read() error: %s",
						strerror (errno));
			return n;
		}

		ah_dbg_old(capwap_htc_info, "read %d bytes from device:", n);
		/*接收到从别的模块来的数据，直接写入到HTTP TUNNEL的OUT接口中*/
		m = tunnel_write (tunnel, buf, (size_t)n);
		ah_dbg_old(capwap_htc_info, "tunnel_write (%p, %p, %d) = %d", tunnel, buf, n, m);
		return m;
	}
	else if (events & POLLHUP)
	{
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: POLLHUP");
		sleep (5);
	}
	else if (events & POLLERR)
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: POLLERR");
	else if (events & POLLNVAL)
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: POLLINVAL");
	else
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: none of the above");

	errno = EIO;
	return -1;
}

	int
handle_tunnel_input (Tunnel *tunnel, int fd, int events)
{
	unsigned char buf[10240];
	ssize_t n, m;

	if (events & POLLIN)
	{
		n = tunnel_read (tunnel, buf, sizeof buf);
		if (n <= 0)
		{
			ah_dbg_old(capwap_htc_info, "handle_tunnel_input: tunnel_read() = %d\n", n);
			if (n == -1 && errno != EAGAIN)
				ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_tunnel_input: tunnel_read() error: %s",
						strerror (errno));
			return n;
		}

		ah_dbg_old(capwap_htc_info, "read %d bytes from tunnel:", n);
		//dump_buf (debug_file, buf, (size_t)n);

		/* If fd == 0, then we are using --stdin-stdout so write to stdout,
		 * not fd. */
		m = write_all (fd ? fd : 0, buf, (size_t)n);
		ah_dbg_old(capwap_htc_info, "write_all (%d, %p, %d) = %d", fd ? fd : 1, buf, n, m);
		return m;
	}
	else if (events & POLLHUP)
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: POLLHUP");
	else if (events & POLLERR)
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: PULLERR");
	else if (events & POLLNVAL)
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: PULLINVAL");
	else
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:handle_device_input: none of the above");

	errno = EIO;
	return -1;
}

	void
name_and_port (const char *nameport, char **name, int *port)
{
	char *p;

	*name = strdup (nameport);
	if (*name == NULL)
	{
		ah_err_old("CAPWAP_TCP:Out of memory\n");
		return;
	}

	p = strchr (*name, ':');
	if (p != NULL)
	{
		*port = atoi (p + 1);
		*p = '\0';
	}        
}

	int
atoi_with_postfix (const char *s_)
{
	char *s;
	int n;
	int factor = 1;
	int x;

	if (s_ == NULL)
	{
		ah_err_old("CAPWAP_TCP:Out of memory\n");
		return -1;
	}

	n = strlen (s_);
	s = (char *)malloc(n+1);
	if(s == NULL) {
	    ah_err_old("%s: Malloc failed\n", __func__);
	    return -1;
	}
	strncpy(s, s_, n+1);
	s[n] = 0;
    
	switch (s[n - 1])
	{
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			break;
		case 'k':
		case 'K':
			factor = 1024;
			break;
		case 'M':
			factor = 1024 * 1024;
			break;
		case 'G':
			factor = 1024 * 1024 * 1024;
			break;
		default:
			ah_err_old("CAPWAP_TCP:Unknown postfix: %c\n", s[n - 1]);
			free(s);
			return -1;
	}

	if (factor != 1)
		s[n - 1] = '\0';

	x = factor * atoi (s);
	free (s);
	return x;
}

#ifdef DEBUG_MODE
	RETSIGTYPE
log_sigpipe (int sig)
{
	ah_dbg_old(htc_basic, "caught SIGPIPE");
	signal (SIGPIPE, log_sigpipe);
}
#endif
