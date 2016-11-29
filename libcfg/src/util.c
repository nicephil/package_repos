/*
 * libcfg - Library for the Unified Configuration Interface
 * Copyright (C) 2008 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

/*
 * This file contains misc utility functions and wrappers to standard
 * functions, which throw exceptions upon failure.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "cfg/cfg.h"
#include "cfg_internal.h"

__private void *cfg_malloc(struct cfg_context *ctx, size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		CFG_THROW(ctx, CFG_ERR_MEM);
	memset(ptr, 0, size);

	return ptr;
}

__private void *cfg_realloc(struct cfg_context *ctx, void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (!ptr)
		CFG_THROW(ctx, CFG_ERR_MEM);

	return ptr;
}

__private char *cfg_strdup(struct cfg_context *ctx, const char *str)
{
	char *ptr;

	ptr = strdup(str);
	if (!ptr)
		CFG_THROW(ctx, CFG_ERR_MEM);

	return ptr;
}

/*
 * validate strings for names and types, reject special characters
 * for names, only alphanum and _ is allowed (shell compatibility)
 * for types, we allow more characters
 */
__private bool cfg_validate_str(const char *str, bool name)
{
	if (!*str)
		return false;

	while (*str) {
		unsigned char c = *str;
		if (!isalnum(c) && c != '_' && c != '/' && c != '-' && c != '@') {
			if (name || (c < 33) || (c > 126))
				return false;
		}
		str++;
	}
	return true;
}

bool cfg_validate_text(const char *str)
{
	while (*str) {
		unsigned char c = *str;
		if ((c == '\r') || (c == '\n') ||
			((c < 32) && (c != '\t')))
			return false;
		str++;
	}
	return true;
}

__private void cfg_alloc_parse_context(struct cfg_context *ctx)
{
	ctx->pctx = (struct cfg_parse_context *) cfg_malloc(ctx, sizeof(struct cfg_parse_context));
}

int cfg_parse_ptr(struct cfg_context *ctx, struct cfg_ptr *ptr, char *str)
{
	char *last = NULL;
	char *tmp;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, str);
	CFG_ASSERT(ctx, ptr);

	memset(ptr, 0, sizeof(struct cfg_ptr));

	/* value */
	last = strchr(str, '=');
	if (last) {
		*last = 0;
		last++;
		ptr->value = last;
	}

	ptr->package = strsep(&str, ".");
	if (!ptr->package)
		goto error;

	ptr->section = strsep(&str, ".");
	if (!ptr->section) {
		ptr->target = CFG_TYPE_PACKAGE;
		goto lastval;
	}

	ptr->option = strsep(&str, ".");
	if (!ptr->option) {
		ptr->target = CFG_TYPE_SECTION;
		goto lastval;
	} else {
		ptr->target = CFG_TYPE_OPTION;
	}

	tmp = strsep(&str, ".");
	if (tmp)
		goto error;

lastval:
	if (ptr->package && !cfg_validate_package(ptr->package))
		goto error;
	if (ptr->section && !cfg_validate_name(ptr->section))
		ptr->flags |= CFG_LOOKUP_EXTENDED;
	if (ptr->option && !cfg_validate_name(ptr->option))
		goto error;
	if (ptr->value && !cfg_validate_text(ptr->value))
		goto error;

	return 0;

error:
	memset(ptr, 0, sizeof(struct cfg_ptr));
	CFG_THROW(ctx, CFG_ERR_PARSE);
}


__private void cfg_parse_error(struct cfg_context *ctx, char *pos, char *reason)
{
	struct cfg_parse_context *pctx = ctx->pctx;

	pctx->reason = reason;
	pctx->byte = pos - pctx->buf;
	CFG_THROW(ctx, CFG_ERR_PARSE);
}



/*
 * open a stream and go to the right position
 *
 * note: when opening for write and seeking to the beginning of
 * the stream, truncate the file
 */
__private FILE *cfg_open_stream(struct cfg_context *ctx, const char *filename, const char *origfilename, int pos, bool write, bool create)
{
	struct stat statbuf;
	FILE *file = NULL;
	int fd, ret;
	int flags = (write ? O_RDWR : O_RDONLY);
	mode_t mode = CFG_FILEMODE;
	char *name = NULL;
	char *filename2 = NULL;

	if (create) {
		flags |= O_CREAT;
		if (origfilename) {
			name = basename((char *) origfilename);
		} else {
			name = basename((char *) filename);
		}
		if ((asprintf(&filename2, "%s/%s", ctx->confdir, name) < 0) || !filename2) {
			CFG_THROW(ctx, CFG_ERR_MEM);
		} else {
			if (stat(filename2, &statbuf) == 0)
				mode = statbuf.st_mode;

			free(filename2);
		}
	}

	if (!write && ((stat(filename, &statbuf) < 0) ||
		((statbuf.st_mode & S_IFMT) != S_IFREG))) {
		CFG_THROW(ctx, CFG_ERR_NOTFOUND);
	}

	fd = open(filename, flags, mode);
	if (fd < 0)
		goto error;

	ret = flock(fd, (write ? LOCK_EX : LOCK_SH));
	if ((ret < 0) && (errno != ENOSYS))
		goto error;

	ret = lseek(fd, 0, pos);

	if (ret < 0)
		goto error;

	file = fdopen(fd, (write ? "w+" : "r"));
	if (file)
		goto done;

error:
	CFG_THROW(ctx, CFG_ERR_IO);
done:
	return file;
}

__private void cfg_close_stream(FILE *stream)
{
	int fd;

	if (!stream)
		return;

	fflush(stream);
	fd = fileno(stream);
	flock(fd, LOCK_UN);
	fclose(stream);
}


