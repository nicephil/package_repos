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
 * This file contains the code for handling cfg config delta files
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "cfg/cfg.h"
#include "cfg_internal.h"

/* record a change that was done to a package */
void
cfg_add_delta(struct cfg_context *ctx, struct cfg_list *list, int cmd, const char *section, const char *option, const char *value)
{
	struct cfg_delta *h;
	int size = strlen(section) + 1;
	char *ptr;

	if (value)
		size += strlen(value) + 1;

	h = cfg_alloc_element(ctx, delta, option, size);
	ptr = cfg_dataptr(h);
	h->cmd = cmd;
	h->section = strcpy(ptr, section);
	if (value) {
		ptr += strlen(ptr) + 1;
		h->value = strcpy(ptr, value);
	}
	cfg_list_add(list, &h->e.list);
}

void
cfg_free_delta(struct cfg_delta *h)
{
	if (!h)
		return;
	if ((h->section != NULL) &&
		(h->section != cfg_dataptr(h))) {
		free(h->section);
		free(h->value);
	}
	cfg_free_element(&h->e);
}


int cfg_set_savedir(struct cfg_context *ctx, const char *dir)
{
	char *sdir;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, dir != NULL);

	sdir = cfg_strdup(ctx, dir);
	if (ctx->savedir != cfg_savedir)
		free(ctx->savedir);
	ctx->savedir = sdir;
	return 0;
}

int cfg_add_delta_path(struct cfg_context *ctx, const char *dir)
{
	struct cfg_element *e;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, dir != NULL);
	e = cfg_alloc_generic(ctx, CFG_TYPE_PATH, dir, sizeof(struct cfg_element));
	cfg_list_add(&ctx->delta_path, &e->list);

	return 0;
}

static inline int cfg_parse_delta_tuple(struct cfg_context *ctx, char **buf, struct cfg_ptr *ptr)
{
	int c = CFG_CMD_CHANGE;

	switch(**buf) {
	case '^':
		c = CFG_CMD_REORDER;
		break;
	case '-':
		c = CFG_CMD_REMOVE;
		break;
	case '@':
		c = CFG_CMD_RENAME;
		break;
	case '+':
		/* CFG_CMD_ADD is used for anonymous sections or list values */
		c = CFG_CMD_ADD;
		break;
	case '|':
		c = CFG_CMD_LIST_ADD;
		break;
	case '~':
		c = CFG_CMD_LIST_DEL;
		break;
	}

	if (c != CFG_CMD_CHANGE)
		*buf += 1;

	CFG_INTERNAL(cfg_parse_ptr, ctx, ptr, *buf);

	if (!ptr->section)
		goto error;
	if (ptr->flags & CFG_LOOKUP_EXTENDED)
		goto error;

	switch(c) {
	case CFG_CMD_REORDER:
		if (!ptr->value || ptr->option)
			goto error;
		break;
	case CFG_CMD_RENAME:
		if (!ptr->value || !cfg_validate_name(ptr->value))
			goto error;
		break;
	case CFG_CMD_LIST_ADD:
		if (!ptr->option)
			goto error;
	case CFG_CMD_LIST_DEL:
		if (!ptr->option)
			goto error;
	}

	return c;

error:
	CFG_THROW(ctx, CFG_ERR_INVAL);
	return 0;
}

static void cfg_parse_delta_line(struct cfg_context *ctx, struct cfg_package *p, char *buf)
{
	struct cfg_element *e = NULL;
	struct cfg_ptr ptr;
	int cmd;

	cmd = cfg_parse_delta_tuple(ctx, &buf, &ptr);
	if (strcmp(ptr.package, p->e.name) != 0)
		goto error;

	if (ctx->flags & CFG_FLAG_SAVED_DELTA)
		cfg_add_delta(ctx, &p->saved_delta, cmd, ptr.section, ptr.option, ptr.value);

	switch(cmd) {
	case CFG_CMD_REORDER:
		cfg_expand_ptr(ctx, &ptr, true);
		if (!ptr.s)
			CFG_THROW(ctx, CFG_ERR_NOTFOUND);
		CFG_INTERNAL(cfg_reorder_section, ctx, ptr.s, strtoul(ptr.value, NULL, 10));
		break;
	case CFG_CMD_RENAME:
		CFG_INTERNAL(cfg_rename, ctx, &ptr);
		break;
	case CFG_CMD_REMOVE:
		CFG_INTERNAL(cfg_delete, ctx, &ptr);
		break;
	case CFG_CMD_LIST_ADD:
		CFG_INTERNAL(cfg_add_list, ctx, &ptr);
		break;
	case CFG_CMD_LIST_DEL:
		CFG_INTERNAL(cfg_del_list, ctx, &ptr);
		break;
	case CFG_CMD_ADD:
	case CFG_CMD_CHANGE:
		CFG_INTERNAL(cfg_set, ctx, &ptr);
		e = ptr.last;
		if (!ptr.option && e && (cmd == CFG_CMD_ADD))
			cfg_to_section(e)->anonymous = true;
		break;
	}
	return;
error:
	CFG_THROW(ctx, CFG_ERR_PARSE);
}

/* returns the number of changes that were successfully parsed */
static int cfg_parse_delta(struct cfg_context *ctx, FILE *stream, struct cfg_package *p)
{
	struct cfg_parse_context *pctx;
	int changes = 0;

	/* make sure no memory from previous parse attempts is leaked */
	cfg_cleanup(ctx);

	pctx = (struct cfg_parse_context *) cfg_malloc(ctx, sizeof(struct cfg_parse_context));
	ctx->pctx = pctx;
	pctx->file = stream;

	while (!feof(pctx->file)) {
		cfg_getln(ctx, 0);
		if (!pctx->buf[0])
			continue;

		/*
		 * ignore parse errors in single lines, we want to preserve as much
		 * delta as possible
		 */
		CFG_TRAP_SAVE(ctx, error);
		cfg_parse_delta_line(ctx, p, pctx->buf);
		CFG_TRAP_RESTORE(ctx);
		changes++;
error:
		continue;
	}

	/* no error happened, we can get rid of the parser context now */
	cfg_cleanup(ctx);
	return changes;
}

/* returns the number of changes that were successfully parsed */
static int cfg_load_delta_file(struct cfg_context *ctx, struct cfg_package *p, char *filename, FILE **f, bool flush)
{
	FILE *stream = NULL;
	int changes = 0;

	CFG_TRAP_SAVE(ctx, done);
	stream = cfg_open_stream(ctx, filename, NULL, SEEK_SET, flush, false);
	if (p)
		changes = cfg_parse_delta(ctx, stream, p);
	CFG_TRAP_RESTORE(ctx);
done:
	if (f)
		*f = stream;
	else if (stream)
		cfg_close_stream(stream);
	return changes;
}

/* returns the number of changes that were successfully parsed */
__private int cfg_load_delta(struct cfg_context *ctx, struct cfg_package *p, bool flush)
{
	struct cfg_element *e;
	char *filename = NULL;
	FILE *f = NULL;
	int changes = 0;

	if (!p->has_delta)
		return 0;

	cfg_foreach_element(&ctx->delta_path, e) {
		if ((asprintf(&filename, "%s/%s", e->name, p->e.name) < 0) || !filename)
			CFG_THROW(ctx, CFG_ERR_MEM);

		cfg_load_delta_file(ctx, p, filename, NULL, false);
		free(filename);
	}

	if ((asprintf(&filename, "%s/%s", ctx->savedir, p->e.name) < 0) || !filename)
		CFG_THROW(ctx, CFG_ERR_MEM);

	changes = cfg_load_delta_file(ctx, p, filename, &f, flush);
	if (flush && f && (changes > 0)) {
		rewind(f);
		if (ftruncate(fileno(f), 0) < 0) {
			cfg_close_stream(f);
			CFG_THROW(ctx, CFG_ERR_IO);
		}
	}
	free(filename);
	cfg_close_stream(f);
	ctx->err = 0;
	return changes;
}

static void cfg_filter_delta(struct cfg_context *ctx, const char *name, const char *section, const char *option)
{
	struct cfg_parse_context *pctx;
	struct cfg_element *e, *tmp;
	struct cfg_list list;
	char *filename = NULL;
	struct cfg_ptr ptr;
	FILE *f = NULL;

	cfg_list_init(&list);
	cfg_alloc_parse_context(ctx);
	pctx = ctx->pctx;

	if ((asprintf(&filename, "%s/%s", ctx->savedir, name) < 0) || !filename)
		CFG_THROW(ctx, CFG_ERR_MEM);

	CFG_TRAP_SAVE(ctx, done);
	f = cfg_open_stream(ctx, filename, NULL, SEEK_SET, true, false);
	pctx->file = f;
	while (!feof(f)) {
		struct cfg_element *e;
		char *buf;

		cfg_getln(ctx, 0);
		buf = pctx->buf;
		if (!buf[0])
			continue;

		/* NB: need to allocate the element before the call to
		 * cfg_parse_delta_tuple, otherwise the original string
		 * gets modified before it is saved */
		e = cfg_alloc_generic(ctx, CFG_TYPE_DELTA, pctx->buf, sizeof(struct cfg_element));
		cfg_list_add(&list, &e->list);

		cfg_parse_delta_tuple(ctx, &buf, &ptr);
		if (section) {
			if (!ptr.section || (strcmp(section, ptr.section) != 0))
				continue;
		}
		if (option) {
			if (!ptr.option || (strcmp(option, ptr.option) != 0))
				continue;
		}
		/* match, drop this element again */
		cfg_free_element(e);
	}

	/* rebuild the delta file */
	rewind(f);
	if (ftruncate(fileno(f), 0) < 0)
		CFG_THROW(ctx, CFG_ERR_IO);
	cfg_foreach_element_safe(&list, tmp, e) {
		fprintf(f, "%s\n", e->name);
		cfg_free_element(e);
	}
	CFG_TRAP_RESTORE(ctx);

done:
	free(filename);
	cfg_close_stream(pctx->file);
	cfg_foreach_element_safe(&list, tmp, e) {
		cfg_free_element(e);
	}
	cfg_cleanup(ctx);
}

int cfg_revert(struct cfg_context *ctx, struct cfg_ptr *ptr)
{
	char *package = NULL;
	char *section = NULL;
	char *option = NULL;

	CFG_HANDLE_ERR(ctx);
	cfg_expand_ptr(ctx, ptr, false);
	CFG_ASSERT(ctx, ptr->p->has_delta);

	/*
	 * - flush unwritten changes
	 * - save the package name
	 * - unload the package
	 * - filter the delta
	 * - reload the package
	 */
	CFG_TRAP_SAVE(ctx, error);
	CFG_INTERNAL(cfg_save, ctx, ptr->p);

	/* NB: need to clone package, section and option names,
	 * as they may get freed on cfg_free_package() */
	package = cfg_strdup(ctx, ptr->p->e.name);
	if (ptr->section)
		section = cfg_strdup(ctx, ptr->section);
	if (ptr->option)
		option = cfg_strdup(ctx, ptr->option);

	cfg_free_package(&ptr->p);
	cfg_filter_delta(ctx, package, section, option);

	CFG_INTERNAL(cfg_load, ctx, package, &ptr->p);
	CFG_TRAP_RESTORE(ctx);
	ctx->err = 0;

error:
	free(package);
	free(section);
	free(option);
	if (ctx->err)
		CFG_THROW(ctx, ctx->err);
	return 0;
}

int cfg_save(struct cfg_context *ctx, struct cfg_package *p)
{
	FILE *f = NULL;
	char *filename = NULL;
	struct cfg_element *e, *tmp;
	struct stat statbuf;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, p != NULL);

	/*
	 * if the config file was outside of the /etc/config path,
	 * don't save the delta to a file, update the real file
	 * directly.
	 * does not modify the cfg_package pointer
	 */
	if (!p->has_delta)
		return cfg_commit(ctx, &p, false);

	if (cfg_list_empty(&p->delta))
		return 0;

	if (stat(ctx->savedir, &statbuf) < 0) {
		if (stat(ctx->confdir, &statbuf) == 0) {
			mkdir(ctx->savedir, statbuf.st_mode);
		} else {
			mkdir(ctx->savedir, CFG_DIRMODE);
		}
	} else if ((statbuf.st_mode & S_IFMT) != S_IFDIR) {
		CFG_THROW(ctx, CFG_ERR_IO);
	}

	if ((asprintf(&filename, "%s/%s", ctx->savedir, p->e.name) < 0) || !filename)
		CFG_THROW(ctx, CFG_ERR_MEM);

	ctx->err = 0;
	CFG_TRAP_SAVE(ctx, done);
	f = cfg_open_stream(ctx, filename, NULL, SEEK_END, true, true);
	CFG_TRAP_RESTORE(ctx);

	cfg_foreach_element_safe(&p->delta, tmp, e) {
		struct cfg_delta *h = cfg_to_delta(e);
		char *prefix = "";

		switch(h->cmd) {
		case CFG_CMD_REMOVE:
			prefix = "-";
			break;
		case CFG_CMD_RENAME:
			prefix = "@";
			break;
		case CFG_CMD_ADD:
			prefix = "+";
			break;
		case CFG_CMD_REORDER:
			prefix = "^";
			break;
		case CFG_CMD_LIST_ADD:
			prefix = "|";
			break;
		case CFG_CMD_LIST_DEL:
			prefix = "~";
			break;
		default:
			break;
		}

		fprintf(f, "%s%s.%s", prefix, p->e.name, h->section);
		if (e->name)
			fprintf(f, ".%s", e->name);

		if (h->cmd == CFG_CMD_REMOVE && !h->value)
			fprintf(f, "\n");
		else
			fprintf(f, "=%s\n", h->value);
		cfg_free_delta(h);
	}

done:
	cfg_close_stream(f);
	free(filename);
	if (ctx->err)
		CFG_THROW(ctx, ctx->err);

	return 0;
}


