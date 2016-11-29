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
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "common.h"
#include "../ah_capwap_def.h"
#include "ah_dcd_api.h"

static inline ssize_t
http_method(int fd, Http_destination *dest,
			Http_method method, ssize_t length)
{
#define AH_CAPWAP_MACADDR_LEN 6
	char str[1500]; /* FIXME: possible buffer overflow */
	Http_request *request;
	ssize_t n;
	uchar      wtpmac[AH_CAPWAP_MACADDR_LEN] = { 0 };

	if (fd == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_method: fd == -1");
		return -1;
	}

	n = 0;
	if (strlen(dest->proxy_name) != 0) {
		n = sprintf(str, "http://%s:%d", dest->host_name, dest->host_port);
	}
	ah_dcd_get_mac_byname(AH_CAPWAP_MGT, (char *)wtpmac);
	sprintf(str + n , "/hm/capwap/index.html?NODEID=%02X%02X%02X%02X%02X%02X",
			wtpmac[0], wtpmac[1], wtpmac[2], wtpmac[3], wtpmac[4], wtpmac[5]);

	request = http_create_request(method, str, 1, 1);
	if (request == NULL) {
		return -1;
	}

	sprintf(str, "%s:%d", dest->host_name, dest->host_port);
	http_add_header(&request->header, "Host", str);

	if (length >= 0) {
		sprintf(str, "%d", length);
		http_add_header(&request->header, "Content-Length", str);
	}

	http_add_header(&request->header, "Connection", "close");
	http_add_header(&request->header, "Pragma", "no-cache");
	http_add_header(&request->header, "Cache-Control", "no-cache, no-store, must-revalidate");

	if (strlen(dest->proxy_authorization) != 0) {
		http_add_header(&request->header,
						"Proxy-Authorization",
						dest->proxy_authorization);
	}

	if (dest->user_agent) {
		http_add_header(&request->header,
						"User-Agent",
						dest->user_agent);
	}

	n = http_write_request(fd, request);
	if (n > 0) {
		ah_capwap_increase_send_bytes_counter((uint32_t)n);
	}
	http_destroy_request(request);
	return n;
}

ssize_t
http_get(int fd, Http_destination *dest)
{
	return http_method(fd, dest, HTTP_GET, -1);
}

ssize_t
http_put(int fd, Http_destination *dest, size_t length)
{
	return http_method(fd, dest, HTTP_PUT, (ssize_t)length);
}

ssize_t
http_post(int fd, Http_destination *dest, size_t length)
{
	return http_method(fd, dest, HTTP_POST, (ssize_t)length);
}

int
http_error_to_errno(int err)
{
	/* Error codes taken from RFC2068. */
	char *errstr = NULL;
	switch (err) {
		case -1: /* system error */
			errstr = "System error";
			return errno;
		case -200: /* OK */
			errstr = "OK";
			goto OUT;
		case -201: /* Created */
			errstr = "Created";
			goto OUT;
		case -202: /* Accepted */
			errstr = "Accepted";
			goto OUT;
		case -203: /* Non-Authoritative Information */
			errstr = "Non-Authoritative Information";
			goto OUT;
		case -204: /* No Content */
			errstr = "No Content";
			goto OUT;
		case -205: /* Reset Content */
			errstr = "Reset Content";
			goto OUT;
		case -206: /* Partial Content */
			return 0;
		case -400: /* Bad Request */
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: 400 bad request");
			return EIO;
		case -401: /* Unauthorized */
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: 401 unauthorized");
			return EACCES;
		case -403: /* Forbidden */
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: 403 forbidden");
			return EACCES;
		case -404: /* Not Found */
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: 404 not found");
			return ENOENT;
		case -411: /* Length Required */
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: 411 length required");
			return EIO;
		case -413: /* Request Entity Too Large */
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: 413 request entity too large");
			return EIO;
		case -505: /* HTTP Version Not Supported       */
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: 505 HTTP version not supported");
			return EIO;
		case -100: /* Continue */
			errstr = "Continue";
			goto OUT;
		case -101: /* Switching Protocols */
			errstr = "Switching Protocols";
			goto OUT;
		case -300: /* Multiple Choices */
			errstr = "Multiple Choices";
			goto OUT;
		case -301: /* Moved Permanently */
			errstr = "Moved Permanently";
			goto OUT;
		case -302: /* Moved Temporarily */
			errstr = "Moved Temporarily";
			goto OUT;
		case -303: /* See Other */
			errstr = "See Other";
			goto OUT;
		case -304: /* Not Modified */
			errstr = "Not Modified";
			goto OUT;
		case -305: /* Use Proxy */
			errstr = "Use Proxy";
			goto OUT;
		case -402: /* Payment Required */
			errstr = "Payment Required";
			goto OUT;
		case -405: /* Method Not Allowed */
			errstr = "Method Not Allowed";
			goto OUT;
		case -406: /* Not Acceptable */
			errstr = "Not Acceptable";
			goto OUT;
		case -407: /* Proxy Autentication Required */
			errstr = "Proxy Autentication Required";
			goto OUT;
		case -408: /* Request Timeout */
			errstr = "Request Timeout";
			goto OUT;
		case -409: /* Conflict */
			errstr = "Conflict";
			goto OUT;
		case -410: /* Gone */
			errstr = "Gone";
			goto OUT;
		case -412: /* Precondition Failed */
			errstr = "Precondition Failed";
			goto OUT;
		case -414: /* Request-URI Too Long */
			errstr = "Request-URI Too Long ";
			goto OUT;
		case -415: /* Unsupported Media Type */
			errstr = "Unsupported Media Type";
			goto OUT;
		case -500: /* Internal Server Error */
			errstr = "Internal Server Error";
			goto OUT;
		case -501: /* Not Implemented */
			errstr = "Not Implemented";
			goto OUT;
		case -502: /* Bad Gateway */
			errstr = "Bad Gateway";
			goto OUT;
		case -503: /* Service Unavailable */
			errstr = "Service Unavailable";
			goto OUT;
		case -504: /* Gateway Timeout */
			errstr = "Gateway Timeout";
			goto OUT;
		default:
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: unknown error %d", err);
			return EIO;
	}
OUT:
	ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:http_error_to_errno: HTTP error code:%d, error string: %s", err,  errstr);
	return EIO;
}

static Http_method
http_string_to_method(const char *method, size_t n)
{
	if (strncmp(method, "GET", n) == 0) {
		return HTTP_GET;
	}
	if (strncmp(method, "PUT", n) == 0) {
		return HTTP_PUT;
	}
	if (strncmp(method, "POST", n) == 0) {
		return HTTP_POST;
	}
	if (strncmp(method, "OPTIONS", n) == 0) {
		return HTTP_OPTIONS;
	}
	if (strncmp(method, "HEAD", n) == 0) {
		return HTTP_HEAD;
	}
	if (strncmp(method, "DELETE", n) == 0) {
		return HTTP_DELETE;
	}
	if (strncmp(method, "TRACE", n) == 0) {
		return HTTP_TRACE;
	}
	return -1;
}

static const char *
http_method_to_string(Http_method method)
{
	switch (method) {
		case HTTP_GET:
			return "GET";
		case HTTP_PUT:
			return "PUT";
		case HTTP_POST:
			return "POST";
		case HTTP_OPTIONS:
			return "OPTIONS";
		case HTTP_HEAD:
			return "HEAD";
		case HTTP_DELETE:
			return "DELETE";
		case HTTP_TRACE:
			return "TRACE";
	}
	return "(uknown)";
}

static ssize_t
read_until(int fd, int ch, unsigned char **data)
{
	unsigned char *buf, *buf2;
	ssize_t n, len, buf_size;

	*data = NULL;

	buf_size = 100;
	buf = malloc(buf_size);
	if (buf == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:read_until: out of memory");
		return -1;
	}
	ah_dbg_old(capwap_htc_info, "read until (%c) start\n", ch);
	len = 0;
	while ((n = read_all(fd, buf + len, 1)) == 1) {
		if (buf[len++] == ch) {
			break;
		}
		if (len + 1 == buf_size) {
			buf_size *= 2;
			buf2 = realloc(buf, buf_size);
			if (buf2 == NULL) {
				ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:read_until: realloc failed");
				free(buf);
				return -1;
			}
			buf = buf2;
		}
	}
	ah_dbg_old(capwap_htc_info, "read until (%c) done\n", ch);
	if (n <= 0) {
		free(buf);
		if (n == 0) {
			ah_log_old(AH_LOG_WARNING, "CAPWAP_TCP:read_until: closed");
		} else {
			ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:read_until: read error: %s", strerror(errno));
		}
		return n;
	}

	/* Shrink to minimum size + 1 in case someone wants to add a NUL. */
	buf2 = realloc(buf, len + 1);
	if (buf2 == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:read_until: realloc: shrink failed");    /* not fatal */
	} else {
		buf = buf2;
	}

	*data = buf;
	return len;
}

static inline Http_header *
http_alloc_header(const char *name, const char *value)
{
	Http_header *header;

	header = malloc(sizeof(Http_header));
	if (header == NULL) {
		return NULL;
	}

	header->name = header->value = NULL;
	header->name = strdup(name);
	header->value = strdup(value);
	if (name == NULL || value == NULL) {
		if (name == NULL) {
			free((char *)name);
		}
		if (value == NULL) {
			free((char *)value);
		}
		free(header);
		return NULL;
	}

	return header;
}

Http_header *
http_add_header(Http_header **header, const char *name, const char *value)
{
	Http_header *new_header;

	new_header = http_alloc_header(name, value);
	if (new_header == NULL) {
		return NULL;
	}

	new_header->next = NULL;
	while (*header) {
		header = &(*header)->next;
	}
	*header = new_header;

	return new_header;
}

static ssize_t
parse_header(int fd, Http_header **header)
{
	unsigned char buf[2];
	unsigned char *data;
	Http_header *h;
	size_t len;
	ssize_t n;

	*header = NULL;

	n = read_all(fd, buf, 2);
	if (n <= 0) {
		return n;
	}
	if (buf[0] == '\r' && buf[1] == '\n') {
		return n;
	}

	h = malloc(sizeof(Http_header));
	if (h == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:parse_header: malloc failed");
		return -1;
	}
	*header = h;
	h->name = NULL;
	h->value = NULL;

	n = read_until(fd, ':', &data);
	if (n <= 0) {
		return n;
	}
	data = realloc(data, n + 2);
	if (data == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:parse_header: realloc failed");
		return -1;
	}
	memmove(data + 2, data, n);
	memcpy(data, buf, 2);
	n += 2;
	data[n - 1] = 0;
	h->name = (const char *)data;
	len = n;

	n = read_until(fd, '\r', &data);
	if (n <= 0) {
		return n;
	}
	data[n - 1] = 0;
	h->value = (const char *)data;
	len += n;

	n = read_until(fd, '\n', &data);
	if (n <= 0) {
		return n;
	}
	free(data);
	if (n != 1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:parse_header: invalid line ending");
		return -1;
	}
	len += n;

	ah_dbg_old(capwap_htc_info, "parse_header: %s:%s", h->name, h->value);

	n = parse_header(fd, &h->next);
	if (n <= 0) {
		return n;
	}
	len += n;

	return len;
}

static ssize_t
http_write_header(int fd, Http_header *header)
{
	ssize_t n = 0, m;

	if (header == NULL) {
		return write_all(fd, "\r\n", 2);
	}

	m = write_all(fd, (void *)header->name, strlen(header->name));
	if (m == -1) {
		return -1;
	}
	n += m;

	m = write_all(fd, ": ", 2);
	if (m == -1) {
		return -1;
	}
	n += m;

	m = write_all(fd, (void *)header->value, strlen(header->value));
	if (m == -1) {
		return -1;
	}
	n += m;

	m = write_all(fd, "\r\n", 2);
	if (m == -1) {
		return -1;
	}
	n += m;
	ah_dbg_old(capwap_htc_info, "http_write_header: %s:%s", header->name, header->value);
	m = http_write_header(fd, header->next);
	if (m == -1) {
		return -1;
	}
	n += m;

	return n;
}

static void
http_destroy_header(Http_header *header)
{
	if (header == NULL) {
		return;
	}

	http_destroy_header(header->next);

	if (header->name) {
		free((char *)header->name);
	}
	if (header->value) {
		free((char *)header->value);
	}
	free(header);
}

static inline Http_response *
http_allocate_response(const char *status_message)
{
	Http_response *response;

	response = malloc(sizeof(Http_response));
	if (response == NULL) {
		return NULL;
	}

	response->status_message = strdup(status_message);
	if (response->status_message == NULL) {
		free(response);
		return NULL;
	}

	return response;
}

Http_response *
http_create_response(int major_version,
					 int minor_version,
					 int status_code,
					 const char *status_message)
{
	Http_response *response;

	response = http_allocate_response(status_message);
	if (response == NULL) {
		return NULL;
	}

	response->major_version = major_version;
	response->minor_version = minor_version;
	response->status_code = status_code;
	response->header = NULL;

	return response;
}

ssize_t
http_parse_response(int fd, Http_response **response_)
{
	Http_response *response;
	unsigned char *data;
	size_t len;
	ssize_t n;

	*response_ = NULL;
	ah_dbg_old(capwap_htc_basic, "Get response from http tunnel server");

	response = malloc(sizeof(Http_response));
	if (response == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_parse_response: out of memory");
		return -1;
	}

	response->major_version = -1;
	response->minor_version = -1;
	response->status_code = -1;
	response->status_message = NULL;
	response->header = NULL;

	n = read_until(fd, '/', &data);
	if (n <= 0) {
		free(response);
		return n;
	} else if (n != 5 || memcmp(data, "HTTP", 4) != 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_parse_response: expected \"HTTP\"");
		free(data);
		free(response);
		return -1;
	}
	if (capwap_htc_detail) {
		ah_hexdump((uchar *)data, n);
	}
	free(data);
	len = n;

	n = read_until(fd, '.', &data);
	if (n <= 0) {
		free(response);
		return n;
	}
	if (capwap_htc_detail) {
		ah_hexdump((uchar *)data, n);
	}
	data[n - 1] = 0;
	response->major_version = atoi((char *)data);
	ah_dbg_old(capwap_htc_info, "http_parse_response: major version = %d",
			   response->major_version);
	free(data);
	len += n;

	n = read_until(fd, ' ', &data);
	if (n <= 0) {
		free(response);
		return n;
	}
	if (capwap_htc_detail) {
		ah_hexdump((uchar *)data, n);
	}
	data[n - 1] = 0;
	response->minor_version = atoi((char *)data);
	ah_dbg_old(capwap_htc_info, "http_parse_response: minor version = %d",
			   response->minor_version);
	free(data);
	len += n;

	n = read_until(fd, ' ', &data);
	if (n <= 0) {
		free(response);
		return n;
	}
	if (capwap_htc_detail) {
		ah_hexdump((uchar *)data, n);
	}
	data[n - 1] = 0;
	response->status_code = atoi((char *)data);
	ah_dbg_old(capwap_htc_info, "http_parse_response: status code = %d",
			   response->status_code);
	free(data);
	len += n;

	n = read_until(fd, '\r', &data);
	if (n <= 0) {
		free(response);
		return n;
	}
	if (capwap_htc_detail) {
		ah_hexdump((uchar *)data, n);
	}
	data[n - 1] = 0;
	response->status_message = (const char *)data;
	ah_dbg_old(capwap_htc_info, "http_parse_response: status message = \"%s\"",
			   response->status_message);
	len += n;

	n = read_until(fd, '\n', &data);
	if (n <= 0) {
		http_destroy_response(response);
		return n;
	}
	if (capwap_htc_detail) {
		ah_hexdump((uchar *)data, n);
	}
	free(data);
	if (n != 1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_parse_request: invalid line ending");
		http_destroy_response(response);
		return -1;
	}
	len += n;

	n = parse_header(fd, &response->header);
	if (n <= 0) {
		http_destroy_response(response);
		return n;
	}
	len += n;

	*response_ = response;
	return len;
}

void
http_destroy_response(Http_response *response)
{
	if (response->status_message) {
		free((char *)response->status_message);
	}
	http_destroy_header(response->header);
	free(response);
}

static inline Http_request *
http_allocate_request(const char *uri)
{
	Http_request *request;

	request = malloc(sizeof(Http_request));
	if (request == NULL) {
		return NULL;
	}

	request->uri = strdup(uri);
	if (request->uri == NULL) {
		free(request);
		return NULL;
	}

	return request;
}

Http_request *
http_create_request(Http_method method,
					const char *uri,
					int major_version,
					int minor_version)
{
	Http_request *request;

	request = http_allocate_request(uri);
	if (request == NULL) {
		return NULL;
	}

	request->method = method;
	request->major_version = major_version;
	request->minor_version = minor_version;
	request->header = NULL;

	return request;
}

ssize_t
http_parse_request(int fd, Http_request **request_)
{
	Http_request *request;
	unsigned char *data;
	size_t len;
	ssize_t n;

	*request_ = NULL;

	request = malloc(sizeof(Http_request));
	if (request == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_parse_request: out of memory");
		return -1;
	}

	request->method = -1;
	request->uri = NULL;
	request->major_version = -1;
	request->minor_version = -1;
	request->header = NULL;

	n = read_until(fd, ' ', &data);
	if (n <= 0) {
		free(request);
		return n;
	}
	request->method = http_string_to_method((const char *)data, n - 1);
	if (request->method == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_parse_request: expected an HTTP method");
		free(data);
		free(request);
		return -1;
	}
	data[n - 1] = 0;
	ah_dbg_old(capwap_htc_info, "http_parse_request: method = \"%s\"", data);
	free(data);
	len = n;

	n = read_until(fd, ' ', &data);
	if (n <= 0) {
		free(request);
		return n;
	}
	data[n - 1] = 0;
	request->uri = (const char *)data;
	len += n;
	ah_dbg_old(capwap_htc_info, "http_parse_request: uri = \"%s\"", request->uri);

	n = read_until(fd, '/', &data);
	if (n <= 0) {
		http_destroy_request(request);
		return n;
	} else if (n != 5 || memcmp(data, "HTTP", 4) != 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_parse_request: expected \"HTTP\"");
		free(data);
		http_destroy_request(request);
		return -1;
	}
	free(data);
	len = n;

	n = read_until(fd, '.', &data);
	if (n <= 0) {
		http_destroy_request(request);
		return n;
	}
	data[n - 1] = 0;
	request->major_version = atoi((char *)data);
	ah_dbg_old(capwap_htc_info, "http_parse_request: major version = %d",
			   request->major_version);
	free(data);
	len += n;

	n = read_until(fd, '\r', &data);
	if (n <= 0) {
		http_destroy_request(request);
		return n;
	}
	data[n - 1] = 0;
	request->minor_version = atoi((char *)data);
	ah_dbg_old(capwap_htc_info, "http_parse_request: minor version = %d",
			   request->minor_version);
	free(data);
	len += n;

	n = read_until(fd, '\n', &data);
	if (n <= 0) {
		http_destroy_request(request);
		return n;
	}
	free(data);
	if (n != 1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_parse_request: invalid line ending");
		http_destroy_request(request);
		return -1;
	}
	len += n;

	n = parse_header(fd, &request->header);
	if (n <= 0) {
		http_destroy_request(request);
		return n;
	}
	len += n;

	*request_ = request;
	return len;
}

ssize_t
http_write_request(int fd, Http_request *request)
{
	char str[1024]; /* FIXME: buffer overflow */
	ssize_t n = 0;
	size_t m;

	m = sprintf(str, "%s %s HTTP/%d.%d\r\n",
				http_method_to_string(request->method),
				request->uri,
				request->major_version,
				request->minor_version);
	m = write_all(fd, str, m);
	ah_dbg_old(capwap_htc_info, "http_write_request: %s", str);
	if (m == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP_TCP:http_write_request: write error: %s", strerror(errno));
		return -1;
	}
	n += m;

	m = http_write_header(fd, request->header);
	if (m == -1) {
		return -1;
	}
	n += m;

	return n;
}

void
http_destroy_request(Http_request *request)
{
	if (request->uri) {
		free((char *)request->uri);
	}
	http_destroy_header(request->header);
	free(request);
}

static Http_header *
http_header_find(Http_header *header, const char *name)
{
	if (header == NULL) {
		return NULL;
	}

	if (strcmp(header->name, name) == 0) {
		return header;
	}

	return http_header_find(header->next, name);
}

const char *
http_header_get(Http_header *header, const char *name)
{
	Http_header *h;

	h = http_header_find(header, name);
	if (h == NULL) {
		return NULL;
	}

	return h->value;
}

