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
#include <string.h>
#include <stdlib.h>

#include "base64.h"
#include "common.h"

static int encode[] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};

/*
   Base64-encode LENGTH bytes of DATA in *CODE, which will be a newly
   malloced area.  *CODE will be a null-terminated string.

   Return -1 on failure, or number of bytes of base64 code on success.
   */

	ssize_t
encode_base64 (const void *data, size_t length, char **code)
{
	const unsigned char *s, *end;
	unsigned char *buf;
	unsigned int x;
	ssize_t n;
	int i, j;

	if (length == 0)
		return 0;

	end = (const unsigned char *)data + length - 3;

	buf = malloc (4 * ((length + 2) / 3) + 1);
	if (buf == NULL)
		return -1;

	n = 0;

	for (s = data; s < end;)
	{
		x = *s++ << 24;
		x |= *s++ << 16;
		x |= *s++ << 8;

		*buf++ = encode[x >> 26];
		x <<= 6;
		*buf++ = encode[x >> 26];
		x <<= 6;
		*buf++ = encode[x >> 26];
		x <<= 6;
		*buf++ = encode[x >> 26];
		n += 4;
	}

	end += 3;

	x = 0;
	for (i = 0; s < end; i++)
		x |= *s++ << (24 - 8 * i);

	for (j = 0; j < 4; j++)
	{
		if (8 * i >= 6 * j)
		{
			*buf++ = encode [x >> 26];
			x <<= 6;
			n++;
		}
		else
		{
			*buf++ = '=';
			n++;
		}
	}

	*buf = 0;

	*code = (char *)buf - n;
	return n;
}
