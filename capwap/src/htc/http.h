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
#include <sys/types.h>
#include <ah_cmd_s.h>

#include "htc.h"

/* All HTTP methods mankind (i.e. RFC2068) knows. */
/* Actually, Netscape has defined some CONNECT method, but */
/* I don't know much about it. */
typedef enum
{
	HTTP_GET,
	HTTP_PUT,
	HTTP_POST,
	HTTP_OPTIONS,
	HTTP_HEAD,
	HTTP_DELETE,
	HTTP_TRACE
} Http_method;

typedef struct http_header Http_header;
struct http_header
{
	const char *name;
	const char *value;
	Http_header *next; /* FIXME: this is ugly; need cons cell. */
};

typedef struct
{
	Http_method method;
	const char *uri;
	int major_version;
	int minor_version;
	Http_header *header;
} Http_request;

typedef struct
{
	int major_version;
	int minor_version;
	int status_code;
	const char *status_message;
	Http_header *header;
} Http_response;

/*base64 output max length*/
#define AH_CAPWAP_HTTP_PROXY_AUTH_STR (((AH_CAPWAP_HTTP_PROXY_AUTH_STR_PARA+2)/3)*4 +10)
typedef struct
{
	char host_name[AH_MAX_STR_PARM_LEN + 1];
	int host_port;
	char proxy_name[AH_MAX_STR_PARM_LEN + 1];
	int proxy_port;
	char proxy_authorization[AH_CAPWAP_HTTP_PROXY_AUTH_STR];
	const char *user_agent;
} Http_destination;

extern ssize_t http_get (int fd, Http_destination *dest);
extern ssize_t http_put (int fd, Http_destination *dest,
		size_t content_length);
extern ssize_t http_post (int fd, Http_destination *dest,
		size_t content_length);
extern int http_error_to_errno (int err);

extern Http_response *http_create_response (int major_version,
		int minor_version,
		int status_code,
		const char *status_message);
extern ssize_t http_parse_response (int fd, Http_response **response);
extern void http_destroy_response (Http_response *response);

extern Http_header *http_add_header (Http_header **header,
		const char *name,
		const char *value);

extern Http_request *http_create_request (Http_method method,
		const char *uri,
		int major_version,
		int minor_version);
extern ssize_t http_parse_request (int fd, Http_request **request);
extern ssize_t http_write_request (int fd, Http_request *request);
extern void http_destroy_request (Http_request *resquest);

extern const char *http_header_get (Http_header *header, const char *name);
