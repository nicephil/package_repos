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
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "http.h"
#include "tunnel.h"
#include "common.h"

/* #define IO_COUNT_HTTP_HEADER */
/* #define USE_SHUTDOWN */

#define READ_TRAIL_TIMEOUT (1 * 1000) /* milliseconds */
#define ACCEPT_TIMEOUT 10 /* seconds */

#define TUNNEL_IN 1
#define TUNNEL_OUT 2

typedef unsigned char Request;

typedef unsigned short Length;


enum tunnel_request {
	TUNNEL_SIMPLE = 0x40,
	TUNNEL_OPEN = 0x01,
	TUNNEL_DATA = 0x02,
	TUNNEL_PADDING = 0x03,
	TUNNEL_ERROR = 0x04,
	TUNNEL_PAD1 = TUNNEL_SIMPLE | 0x05,
	TUNNEL_CLOSE = TUNNEL_SIMPLE | 0x06,
	TUNNEL_DISCONNECT = TUNNEL_SIMPLE | 0x07
};

static inline const char *
REQ_TO_STRING(Request request)
{
	switch (request) {
		case TUNNEL_OPEN:
			return "TUNNEL_OPEN";
		case TUNNEL_DATA:
			return "TUNNEL_DATA";
		case TUNNEL_PADDING:
			return "TUNNEL_PADDING";
		case TUNNEL_ERROR:
			return "TUNNEL_ERROR";
		case TUNNEL_PAD1:
			return "TUNNEL_PAD1";
		case TUNNEL_CLOSE:
			return "TUNNEL_CLOSE";
		case TUNNEL_DISCONNECT:
			return "TUNNEL_DISCONNECT";
		default:
			return "(unknown)";
	}
}

struct tunnel {
	int in_fd, out_fd;
	int server_socket;
	Http_destination dest;
	struct sockaddr_in address;
	size_t bytes;
	size_t content_length;
	char buf[65536];
	char *buf_ptr;
	size_t buf_len;
	int padding_only;
	size_t in_total_raw;
	size_t in_total_data;
	size_t out_total_raw;
	size_t out_total_data;
	time_t out_connect_time;
	int strict_content_length;
	int keep_alive;
	int max_connection_age;
};

static const size_t sizeof_header = sizeof(Request) + sizeof(Length);

static inline int
tunnel_is_disconnected(Tunnel *tunnel)
{
	return tunnel->out_fd == -1;
}

static inline int
tunnel_is_connected(Tunnel *tunnel)
{
	return !tunnel_is_disconnected(tunnel);
}

static inline int
tunnel_is_client(Tunnel *tunnel)
{
	return 1;
}
int
get_proto_number(const char *name)
{
	struct protoent *p;
	int number;

	p = getprotobyname(name);
	if (p == NULL) {
		number = -1;
	} else {
		number = p->p_proto;
	}
	endprotoent();

	return number;
}

static int
tunnel_in_setsockopts(int fd)
{
	return 0;
}

static int
tunnel_out_setsockopts(int fd)
{
	int i = 0;

	i = 64 * 1024; /*default is 16K (most 16 packet), enlarge it*/
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&i, sizeof i) == -1) {
		ah_err_old("%s: Set socket option(SO_SNDBUF) failed.", __func__);
		return -1;
	}

	i = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&i, sizeof i) == -1) {
		ah_err_old("%s: Set socket option(SO_KEEPALIVE) failed.", __func__);
		return -1;
	}

	return 0;
}

static void
tunnel_out_disconnect(Tunnel *tunnel)
{
	if (tunnel_is_disconnected(tunnel)) {
		return;
	}

	if (tunnel_is_client(tunnel) &&
			tunnel->bytes != tunnel->content_length + 1)
		ah_dbg_old(capwap_htc_info, "CAPWAP_TCP:tunnel_out_disconnect: warning: "
				   "bytes=%d != content_length=%d",
				   tunnel->bytes, tunnel->content_length + 1);

	close(tunnel->out_fd);
	tunnel->out_fd = -1;
	tunnel->bytes = 0;
	tunnel->buf_ptr = tunnel->buf;
	tunnel->buf_len = 0;

	ah_dbg_old(capwap_htc_basic, "tunnel_out_disconnect: output disconnected");
}

static void
tunnel_in_disconnect(Tunnel *tunnel)
{
	if (tunnel->in_fd == -1) {
		return;
	}

	close(tunnel->in_fd);
	tunnel->in_fd = -1;

	ah_dbg_old(capwap_htc_basic, "tunnel_in_disconnect: input disconnected");
}

static int
tunnel_out_connect(Tunnel *tunnel)
{
	ssize_t n;
	Http_response *response = NULL;
	int rc = 0;

	ah_dbg_old(capwap_htc_basic, "tunnel_out_connect: ready setup the out connection");
	if (tunnel_is_connected(tunnel)) {
		ah_dbg_old(capwap_htc_basic, "tunnel_out_connect: already connected");
		tunnel_out_disconnect(tunnel);
	}
	tunnel->out_fd = do_connect(&tunnel->address);
	if (tunnel->out_fd == -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP_TCP:tunnel_out_connect: do_connect (ip:%i port:%d) error: %s",
				   (int)(tunnel->address.sin_addr.s_addr),
				   ntohs(tunnel->address.sin_port),
				   strerror(errno));
		return -1;
	}
	tunnel_out_setsockopts(tunnel->out_fd);

#ifdef USE_SHUTDOWN
	shutdown(tunnel->out_fd, 0);
#endif

	n = http_post(tunnel->out_fd,
				  &tunnel->dest,
				  tunnel->content_length + 1);
	if (n == -1) {
		return -1;
	}

	ah_sleep(1);
	rc = http_parse_response(tunnel->out_fd, &response);
	if (rc <= 0) {
		/*do nothing*/
	} else if (response != NULL && response->status_code != 200) {
		http_error_to_errno(-response->status_code);
		http_destroy_response(response);
		return -1;
	}

	if (response) {
		http_destroy_response(response);
	}

#ifdef IO_COUNT_HTTP_HEADER
	tunnel->out_total_raw += n;
	ah_dbg_old(capwap_htc_info, "tunnel_out_connect: out_total_raw = %u",
			   tunnel->out_total_raw);
#endif

	tunnel->bytes = 0;
	tunnel->buf_ptr = tunnel->buf;
	tunnel->buf_len = 0;
	tunnel->padding_only = TRUE;

	time(&tunnel->out_connect_time);

	ah_dbg_old(capwap_htc_basic, "tunnel_out_connect: output connected");

	return 0;
}

int
tunnel_in_connect(Tunnel *tunnel)
{
	Http_response *response;
	ssize_t n;

	ah_dbg_old(capwap_htc_info, "tunnel_in_connect()");
	if (tunnel == NULL) {
		return -1;
	}
	if (tunnel->in_fd != -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP_TCP:tunnel_in_connect: already connected");
		return -1;
	}

	tunnel->in_fd = do_connect(&tunnel->address);
	if (tunnel->in_fd == -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP_TCP:tunnel_in_connect: do_connect() error: %s",
				   strerror(errno));
		return -1;
	}

	tunnel_in_setsockopts(tunnel->in_fd);

	if (http_get(tunnel->in_fd, &tunnel->dest) == -1) {
		return -1;
	}

#ifdef USE_SHUTDOWN
	if (shutdown(tunnel->in_fd, 1) == -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP_TCP:tunnel_in_connect: shutdown() error: %s",
				   strerror(errno));
		return -1;
	}
#endif
	ah_sleep(1);
	n = http_parse_response(tunnel->in_fd, &response);
	if (n <= 0) {
		if (n == 0)
			ah_dbg_old(capwap_htc_info, "CAPWAP_TCP:tunnel_in_connect: no response; peer "
					   "closed connection");
		else
			ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:tunnel_in_connect: no response; error: %s",
					   strerror(errno));
	} else if (response->major_version != 1 ||
			   (response->minor_version != 1 &&
				response->minor_version != 0)) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:tunnel_in_connect: unknown HTTP version: %d.%d",
				   response->major_version, response->minor_version);
		n = -1;
	} else if (response->status_code != 200) {
		//ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:tunnel_in_connect: HTTP error %d", response->status_code);
		errno = http_error_to_errno(-response->status_code);
		n = -1;
	}

	if (response) {
		http_destroy_response(response);
	}

	if (n > 0) {
#ifdef IO_COUNT_HTTP_HEADER
		tunnel->in_total_raw += n;
		ah_dbg_old(capwap_htc_info, "tunnel_in_connect: in_total_raw = %u",
				   tunnel->in_total_raw);
#endif
	} else {
		ah_dbg_old(capwap_htc_basic, "Get an error in setup a IN CAPWAP_TCP connection.");
		return n;
	}

	ah_dbg_old(capwap_htc_basic, "tunnel_in_connect: input connected");
	return 1;
}

static inline ssize_t
tunnel_write_data(Tunnel *tunnel, void *data, size_t length)
{
	if (write_all(tunnel->out_fd, data, length) == -1) {
		if (errno != EPIPE) {
			Request type ;
			memcpy(&type, data, sizeof(Request));
			ah_log_old(AH_LOG_INFO, "CAPWAP_TCP:tunnel_write_data: write error: %s, type:%s", strerror(errno),
					   (length == 1 ? REQ_TO_STRING(type) : "Other"));
		}
		return -1;
	}

	tunnel->bytes += length;
	return length;
}

static int
tunnel_write_request(Tunnel *tunnel, Request request,
					 void *data, Length length)
{
	if (tunnel->bytes + sizeof request +
			(data ? sizeof length + length : 0) > tunnel->content_length) { /*TLV ?*/
		tunnel_padding(tunnel, tunnel->content_length - tunnel->bytes);
	}

	if (tunnel_is_disconnected(tunnel)) {
		if (tunnel_is_client(tunnel)) {
			if (tunnel_out_connect(tunnel) == -1) {
				return -1;
			}
		}
	}

	if (request != TUNNEL_PADDING && request != TUNNEL_PAD1) {
		tunnel->padding_only = FALSE;
	}

	ah_dbg_old(capwap_htc_info, "write type %s to request", REQ_TO_STRING(request));
	if (tunnel_write_data(tunnel, &request, sizeof request) == -1) {
		if (errno != EPIPE) {
			return -1;
		}

		tunnel_out_disconnect(tunnel);
		if (tunnel_is_client(tunnel)) {
			tunnel_out_connect(tunnel);
		} else {
			ah_log_old(AH_LOG_INFO, "CAPWAP_TCP:tunnel_write_request: couldn't write request: "
					   "output is disconnected");
			errno = EIO;
			return -1;
		}
		/* return tunnel_write_request (tunnel, request, data, length); */
		if (tunnel_write_data(tunnel, &request, sizeof request) == -1) {
			return -1;
		}
	}
	if (data) {
		Length network_length = htons((short)length);
		ah_dbg_old(capwap_htc_info, "write length %d to request", network_length);
		if (tunnel_write_data(tunnel, &network_length, sizeof network_length) == -1) {
			return -1;
		}
		ah_dbg_old(capwap_htc_info, "tunnel_write_request: TUNNEL_DATA:");
		if (request == TUNNEL_DATA && capwap_htc_detail) {
			ah_hexdump((uchar *)data, (size_t)length);
		}
		if (tunnel_write_data(tunnel, data, (size_t)length) == -1) {
			return -1;
		}
	}

	if (data) {
		tunnel->out_total_raw += 3 + length;

		if (request == TUNNEL_DATA)
			ah_dbg_old(capwap_htc_info, "tunnel_write_request: %s (length=%d)",
					   REQ_TO_STRING(request), length);
		else
			ah_dbg_old(capwap_htc_basic, "tunnel_write_request: %s (length=%d)",
					   REQ_TO_STRING(request), length);
	} else {
		tunnel->out_total_raw += 1;
		ah_dbg_old(capwap_htc_basic, "tunnel_write_request: %s", REQ_TO_STRING(request));
	}

	ah_dbg_old(capwap_htc_info, "tunnel_write_data: out_total_raw = %u, total bytes = %u",
			   tunnel->out_total_raw, tunnel->bytes);

	if (tunnel->bytes > tunnel->content_length) {
		ah_dbg_old(capwap_htc_basic, "tunnel_write_request: tunnel->bytes > tunnel->content_length");
	}

	if (tunnel->bytes >= tunnel->content_length) {
		char c = TUNNEL_DISCONNECT;
		ah_dbg_old(capwap_htc_basic, "the write data length (%d) exceed the max content bytes, need disconnect", tunnel->bytes);
		ah_dbg_old(capwap_htc_basic, "tunnel_write_request: %s (length=%d)",
				   REQ_TO_STRING(c), sizeof c);
		(void)tunnel_write_data(tunnel, &c, sizeof c);
		tunnel_out_disconnect(tunnel);
		return -1;
	}

	return length;
}

int
tunnel_connect(Tunnel *tunnel)
{
	char auth_data[1] = { 42 }; /* dummy data, not used by server */

	if (tunnel_is_connected(tunnel)) {
		ah_log_old(AH_LOG_INFO, "CAPWAP_TCP:tunnel_connect: already connected");
		errno = EINVAL;
		return -1;
	}
	if (tunnel_write_request(tunnel, TUNNEL_OPEN,
							 auth_data, sizeof auth_data) == -1) {
		return -1;
	}

	if (tunnel_in_connect(tunnel) <= 0) {
		return -1;
	}

	return 0;
}

static inline int
tunnel_write_or_padding(Tunnel *tunnel, Request request, void *data,
						size_t length)
{
	static char padding[65536];
	size_t n, remaining;
	char *wdata = data;

	for (remaining = length; remaining > 0; remaining -= n, wdata += n) {
		if (tunnel->bytes + remaining > tunnel->content_length - sizeof_header &&
				tunnel->content_length - tunnel->bytes > sizeof_header) {
			n = tunnel->content_length - sizeof_header - tunnel->bytes;
		} else if (remaining > tunnel->content_length - sizeof_header) {
			n = tunnel->content_length - sizeof_header;
		} else {
			n = remaining;
		}

		if (n > 65535) {
			n = 65535;
		}

		if (request == TUNNEL_PADDING) {
			if (n + sizeof_header > remaining) {
				n = remaining - sizeof_header;
			}
			if (tunnel_write_request(tunnel, request, padding, n) == -1) {
				break;
			}
			n += sizeof_header;
		} else {
			if (tunnel_write_request(tunnel, request, wdata, n) == -1) {
				break;
			}
		}
	}

	return length - remaining;
}

ssize_t
tunnel_write(Tunnel *tunnel, void *data, size_t length)
{
	ssize_t n = 0;

	if (!tunnel) {
		ah_log_old(AH_LOG_INFO, "CAPWAP_TCP: Tunnel has broken, skip this send");
		return -1;
	}
	if ((tunnel->bytes + length) >= (tunnel->content_length - sizeof_header)) {
		n = tunnel_padding(tunnel, (tunnel->content_length - tunnel->bytes));
		if (n > 0) {
			tunnel->out_total_data += n;
		}
		ah_dbg_old(capwap_htc_basic, "tunnel_write: out_total_data = %u, padding actual= %u", tunnel->out_total_data, n);
		tunnel_out_connect(tunnel);
	}
	n = tunnel_write_or_padding(tunnel, TUNNEL_DATA, data, length);
	if (n <= 0) {
		ah_dbg_old(capwap_htc_basic, "tunnel_write: write data failed, try again!");
		/*retry*/
		n = tunnel_write_or_padding(tunnel, TUNNEL_DATA, data, length);
		if (n > 0) {
			tunnel->out_total_data += n;
		}
	}
	ah_dbg_old(capwap_htc_basic, "tunnel_write: out_total_data = %u, data actual= %u", tunnel->out_total_data, n);

	return n;
}

ssize_t
tunnel_padding(Tunnel *tunnel, size_t length)
{
	if (length < sizeof_header + 1) {
		int i;

		for (i = 0; i < length; i++) {
			tunnel_write_request(tunnel, TUNNEL_PAD1, NULL, 0);
		}
		return length;
	}
	return tunnel_write_or_padding(tunnel, TUNNEL_PADDING, NULL, length);
}

static int
tunnel_read_request(Tunnel *tunnel, enum tunnel_request *request,
					unsigned char *buf, size_t *length)
{
	Request req;
	Length len;
	ssize_t n;

	n = read(tunnel->in_fd, &req, 1);
	ah_dbg_old(capwap_htc_info, "Read from fd:%d to get type ", tunnel->in_fd);
	if (n == -1) {
		if (errno != EAGAIN)
			ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:tunnel_read_request: error reading request: %s",
					   strerror(errno));
		return n;
	} else if (n == 0) {
		ah_dbg_old(capwap_htc_basic, "tunnel_read_request: connection closed by peer");
		tunnel_in_disconnect(tunnel);
#if 0
		if (tunnel_is_client(tunnel)
				&& tunnel_in_connect(tunnel) == -1) {
			return -1;
		}
#endif
		errno = EAGAIN;
		return -1;
	}
	*request = req;
	tunnel->in_total_raw += n;
	ah_dbg_old(capwap_htc_info, "request type = 0x%x (%s)", req, REQ_TO_STRING(req));

	if (req & TUNNEL_SIMPLE) {
		ah_dbg_old(capwap_htc_info, "tunnel_read_request: in_total_raw = %u",
				   tunnel->in_total_raw);
		ah_dbg_old(capwap_htc_basic, "tunnel_read_request:  %s", REQ_TO_STRING(req));
		*length = 0;
		return 1;
	}

	ah_dbg_old(capwap_htc_info, "Read from fd:%d to get length ", tunnel->in_fd);
	n = read_all(tunnel->in_fd, &len, 2);
	if (n <= 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:tunnel_read_request: error reading request length: %s",
				   strerror(errno));
		if (n == 0) {
			errno = EIO;
		}
		return -1;
	}
	len = ntohs(len);
	*length = len;
	tunnel->in_total_raw += n;
	ah_dbg_old(capwap_htc_info, "request length = %d", len);

	if (len > 0) {
		ah_dbg_old(capwap_htc_info, "Read from fd:%d to get value ", tunnel->in_fd);
		n = read_all(tunnel->in_fd, buf, (size_t)len);
		if (n <= 0) {
			ah_dbg_old(capwap_htc_basic, "CAPWAP_TCP:tunnel_read_request: error reading request data: %s",
					   strerror(errno));
			if (n == 0) {
				errno = EIO;
			}
			return -1;
		}
		if (capwap_htc_detail) {
			ah_hexdump((uchar *)buf, n);
		}
		tunnel->in_total_raw += n;
		ah_dbg_old(capwap_htc_info, "tunnel_read_request: in_total_raw = %u",
				   tunnel->in_total_raw);
	}

	if (req == TUNNEL_DATA)
		ah_dbg_old(capwap_htc_info, "tunnel_read_request:  %s (length=%d)",
				   REQ_TO_STRING(req), len);
	else
		ah_dbg_old(capwap_htc_basic, "tunnel_read_request:  %s (length=%d)",
				   REQ_TO_STRING(req), len);

	return 1;
}

ssize_t
tunnel_read(Tunnel *tunnel, void *data, size_t length)
{
	enum tunnel_request req;
	size_t len;
	ssize_t n;

	if (tunnel == NULL) {
		return -1;
	}
	if (tunnel->buf_len > 0) {
		n = min(tunnel->buf_len, length);
		memcpy(data, tunnel->buf_ptr, n);
		tunnel->buf_ptr += n;
		tunnel->buf_len -= n;
		return n;
	}

	if (tunnel->in_fd == -1) {
		if (tunnel_is_client(tunnel)) {
			if (tunnel_in_connect(tunnel) <= 0) {
				return -1;
			}
		}
		errno = EAGAIN;
		return -1;
	}

	if (tunnel_read_request(tunnel, &req, (unsigned char *) tunnel->buf, &len) <= 0) {
		ah_dbg_old(capwap_htc_info, "tunnel_read_request returned <= 0, return -1");
		return -1;
	}

	switch (req) {
		case TUNNEL_OPEN:
			/* do something with tunnel->buf */
			break;

		case TUNNEL_DATA:
			tunnel->buf_ptr = tunnel->buf;
			tunnel->buf_len = len;
			tunnel->in_total_data += len;
			ah_dbg_old(capwap_htc_basic, "tunnel_read: in_total_data = %u, actual len:%u", tunnel->in_total_data, len);
			return tunnel_read(tunnel, data, length);

		case TUNNEL_PADDING:
			/* discard data */
			break;

		case TUNNEL_PAD1:
			/* do nothing */
			break;

		case TUNNEL_ERROR:
			tunnel->buf[len] = 0;
			ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:tunnel_read: received error: %s", tunnel->buf);
			errno = EIO;
			return -1;

		case TUNNEL_CLOSE:
			return 0;

		case TUNNEL_DISCONNECT:
			ah_dbg_old(capwap_htc_basic, "Receive peer disconnect command, In tcp tunnel reconnect");
			tunnel_in_disconnect(tunnel);
			if (tunnel_is_client(tunnel)
					&& tunnel_in_connect(tunnel) == -1) {
				return -1;
			}

			errno = EAGAIN;
			return -1;

		default:
			ah_dbg_old(capwap_htc_basic, "CAPWAP_TCP:tunnel_read: protocol error: unknown request 0x%02x", req);
			errno = EINVAL;
			return -1;
	}

	errno = EAGAIN;
	return -1;
}

int
tunnel_pollin_fd(Tunnel *tunnel)
{

	if (tunnel != NULL && tunnel->in_fd != -1) {
		return tunnel->in_fd;
	} else {
		ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:tunnel_pollin_fd: returning -1");
		return -1;
	}
}

int
tunnel_pollout_fd(Tunnel *tunnel)
{
	if (tunnel->out_fd != -1) {
		return tunnel->out_fd;
	} else {
		ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:tunnel_pollout_fd: returning -1");
		return -1;
	}
}

Tunnel *
tunnel_new_client(const char *host, int host_port,
				  const char *proxy, int proxy_port,
				  size_t content_length)
{
	char remote[AH_MAX_STR_PARM_LEN + 1];
	int remote_port;
	Tunnel *tunnel;

	ah_dbg_old(capwap_htc_info, "tunnel_new_client (\"%s\", %d, \"%s\", %d, %d)",
			   host, host_port, proxy ? proxy : "(null)", proxy_port,
			   content_length);

	tunnel = malloc(sizeof(Tunnel));
	if (tunnel == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:tunnel_new_client: out of memory");
		return NULL;
	}

	tunnel->in_fd = -1;
	tunnel->out_fd = -1;
	tunnel->server_socket = -1;
	//tunnel->dest.host_name = host;
	strcpy(tunnel->dest.host_name, host);
	tunnel->dest.host_port = host_port;
	//tunnel->dest.proxy_name = proxy;
	strcpy(tunnel->dest.proxy_name, proxy);
	tunnel->dest.proxy_port = proxy_port;
	//tunnel->dest.proxy_authorization = NULL;
	strcpy(tunnel->dest.proxy_authorization, "");
	tunnel->dest.user_agent = NULL;
	/* -1 to allow for TUNNEL_DISCONNECT */
	tunnel->content_length = content_length - 1;
	tunnel->buf_ptr = tunnel->buf;
	tunnel->buf_len = 0;
	tunnel->in_total_raw = 0;
	tunnel->in_total_data = 0;
	tunnel->out_total_raw = 0;
	tunnel->out_total_data = 0;
	tunnel->strict_content_length = FALSE;
	tunnel->bytes = 0;

	if (strlen(tunnel->dest.proxy_name) == 0) {
		//remote = tunnel->dest.host_name;
		strcpy(remote, tunnel->dest.host_name);
		remote_port = tunnel->dest.host_port;
	} else {
		//remote = tunnel->dest.proxy_name;
		strcpy(remote, tunnel->dest.proxy_name);
		remote_port = tunnel->dest.proxy_port;
	}

	if (set_address(&tunnel->address, remote, remote_port) == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:tunnel_new_client: set_address: %s", strerror(errno));
		free(tunnel);
		return NULL;
	}

	return tunnel;
}

static int
tunnel_opt(Tunnel *tunnel, const char *opt, void *data, int get_flag)
{
	if (strcmp(opt, "strict_content_length") == 0) {
		if (get_flag) {
			*(int *)data = tunnel->strict_content_length;
		} else {
			tunnel->strict_content_length = *(int *)data;
		}
	} else if (strcmp(opt, "keep_alive") == 0) {
		if (get_flag) {
			*(int *)data = tunnel->keep_alive;
		} else {
			tunnel->keep_alive = *(int *)data;
		}
	} else if (strcmp(opt, "max_connection_age") == 0) {
		if (get_flag) {
			*(int *)data = tunnel->max_connection_age;
		} else {
			tunnel->max_connection_age = *(int *)data;
		}
	} else if (strcmp(opt, "proxy_authorization") == 0) {
		if (get_flag) {
			/**************************
			  if (strlen(tunnel->dest.proxy_authorization) == 0)
			 *(char **)data = NULL;
			 else
			 *(char **)data = strdup (tunnel->dest.proxy_authorization);
			 ***************/
		} else {
			if (strlen((char *)data) >= AH_CAPWAP_HTTP_PROXY_AUTH_STR) {
				ah_log_old(AH_LOG_ERR, "CAPWAP_TCP: the proxy authorization length :%d exceed the max length %d\n", strlen((char *)data),
						   (AH_CAPWAP_HTTP_PROXY_AUTH_STR - 1));
				return -1;
			}
			strcpy(tunnel->dest.proxy_authorization, (char *)data);
			if (strlen(tunnel->dest.proxy_authorization) == 0) {
				return -1;
			}
		}
	} else if (strcmp(opt, "user_agent") == 0) {
		if (get_flag) {
			if (tunnel->dest.user_agent == NULL) {
				*(char **)data = NULL;
			} else {
				*(char **)data = strdup(tunnel->dest.user_agent);
			}
		} else {
			if (tunnel->dest.user_agent != NULL) {
				free((char *)tunnel->dest.user_agent);
			}
			tunnel->dest.user_agent = strdup((char *)data);
			if (tunnel->dest.user_agent == NULL) {
				return -1;
			}
		}
	} else {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int
tunnel_setopt(Tunnel *tunnel, const char *opt, void *data)
{
	return tunnel_opt(tunnel, opt, data, FALSE);
}

int
tunnel_getopt(Tunnel *tunnel, const char *opt, void *data)
{
	return tunnel_opt(tunnel, opt, data, TRUE);
}

int
tunnel_close(Tunnel *tunnel)
{
	ah_dbg_old(capwap_htc_basic, "tunnel_close: free all tunnel resource");
	//tunnel_write_request (tunnel, TUNNEL_CLOSE, NULL, 0);

	tunnel_out_disconnect(tunnel);

	tunnel_in_disconnect(tunnel);

	tunnel->buf_len = 0;
	tunnel->in_total_raw = 0;
	tunnel->in_total_data = 0;
	tunnel->out_total_raw = 0;
	tunnel->out_total_data = 0;

	return 0;

}

