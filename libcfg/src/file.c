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
 * This file contains the code for parsing cfg config files
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
#include <glob.h>
#include <string.h>
#include <stdlib.h>

#include "cfg.h"
#include "cfg_internal.h"

#define LINEBUF	32
#define LINEBUF_MAX	4096

/*
 * Fetch a new line from the input stream and resize buffer if necessary
 */
__private void cfg_getln(struct cfg_context *ctx, int offset)
{
	struct cfg_parse_context *pctx = ctx->pctx;
	char *p;
	int ofs;

	if (pctx->buf == NULL) {
		pctx->buf = cfg_malloc(ctx, LINEBUF);
		pctx->bufsz = LINEBUF;
	}

	ofs = offset;
	do {
		p = &pctx->buf[ofs];
		p[ofs] = 0;

		p = fgets(p, pctx->bufsz - ofs, pctx->file);
		if (!p || !*p)
			return;

		ofs += strlen(p);
		if (pctx->buf[ofs - 1] == '\n') {
			pctx->line++;
			if (ofs >= 2 && pctx->buf[ofs - 2] == '\r')
				pctx->buf[ofs - 2] = 0;
			else
				pctx->buf[ofs - 1] = 0;
			return;
		}

		if (pctx->bufsz > LINEBUF_MAX/2)
			cfg_parse_error(ctx, p, "line too long");

		pctx->bufsz *= 2;
		pctx->buf = cfg_realloc(ctx, pctx->buf, pctx->bufsz);
	} while (1);
}


/*
 * parse a character escaped by '\'
 * returns true if the escaped character is to be parsed
 * returns false if the escaped character is to be ignored
 */
static inline bool parse_backslash(struct cfg_context *ctx, char **str)
{
	/* skip backslash */
	*str += 1;

	/* undecoded backslash at the end of line, fetch the next line */
	if (!**str) {
		*str += 1;
		cfg_getln(ctx, *str - ctx->pctx->buf);
		return false;
	}

	/* FIXME: decode escaped char, necessary? */
	return true;
}

/*
 * move the string pointer forward until a non-whitespace character or
 * EOL is reached
 */
static void skip_whitespace(struct cfg_context *ctx, char **str)
{
restart:
	while (**str && isspace(**str))
		*str += 1;

	if (**str == '\\') {
		if (!parse_backslash(ctx, str))
			goto restart;
	}
}

static inline void addc(char **dest, char **src)
{
	**dest = **src;
	*dest += 1;
	*src += 1;
}

/*
 * parse a double quoted string argument from the command line
 */
static void parse_double_quote(struct cfg_context *ctx, char **str, char **target)
{
	char c;

	/* skip quote character */
	*str += 1;

	while ((c = **str)) {
		switch(c) {
		case '"':
			**target = 0;
			*str += 1;
			return;
		case '\\':
			if (!parse_backslash(ctx, str))
				continue;
			/* fall through */
		default:
			addc(target, str);
			break;
		}
	}
	cfg_parse_error(ctx, *str, "unterminated \"");
}

/*
 * parse a single quoted string argument from the command line
 */
static void parse_single_quote(struct cfg_context *ctx, char **str, char **target)
{
	char c;
	/* skip quote character */
	*str += 1;

	while ((c = **str)) {
		switch(c) {
		case '\'':
			**target = 0;
			*str += 1;
			return;
		default:
			addc(target, str);
		}
	}
	cfg_parse_error(ctx, *str, "unterminated '");
}

/*
 * parse a string from the command line and detect the quoting style
 */
static void parse_str(struct cfg_context *ctx, char **str, char **target)
{
	bool next = true;
	do {
		switch(**str) {
		case '\'':
			parse_single_quote(ctx, str, target);
			break;
		case '"':
			parse_double_quote(ctx, str, target);
			break;
		case '#':
			**str = 0;
			/* fall through */
		case 0:
			goto done;
		case ';':
			next = false;
			goto done;
		case '\\':
			if (!parse_backslash(ctx, str))
				continue;
			/* fall through */
		default:
			addc(target, str);
			break;
		}
	} while (**str && !isspace(**str));
done:

	/*
	 * if the string was unquoted and we've stopped at a whitespace
	 * character, skip to the next one, because the whitespace will
	 * be overwritten by a null byte here
	 */
	if (**str && next)
		*str += 1;

	/* terminate the parsed string */
	**target = 0;
}

/*
 * extract the next argument from the command line
 */
static char *next_arg(struct cfg_context *ctx, char **str, bool required, bool name)
{
	char *val;
	char *ptr;

	val = ptr = *str;
	skip_whitespace(ctx, str);
	if(*str[0] == ';') {
		*str[0] = 0;
		*str += 1;
	} else {
		parse_str(ctx, str, &ptr);
	}
	if (!*val) {
		if (required)
			cfg_parse_error(ctx, *str, "insufficient arguments");
		goto done;
	}

	if (name && !cfg_validate_name(val))
		cfg_parse_error(ctx, val, "invalid character in field");

done:
	return val;
}

int cfg_parse_argument(struct cfg_context *ctx, FILE *stream, char **str, char **result)
{
	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, str != NULL);
	CFG_ASSERT(ctx, result != NULL);

	if (ctx->pctx && (ctx->pctx->file != stream))
		cfg_cleanup(ctx);

	if (!ctx->pctx)
		cfg_alloc_parse_context(ctx);

	ctx->pctx->file = stream;

	if (!*str) {
		cfg_getln(ctx, 0);
		*str = ctx->pctx->buf;
	}

	*result = next_arg(ctx, str, false, false);

	return 0;
}

static int
cfg_fill_ptr(struct cfg_context *ctx, struct cfg_ptr *ptr, struct cfg_element *e)
{
	CFG_ASSERT(ctx, ptr != NULL);
	CFG_ASSERT(ctx, e != NULL);

	memset(ptr, 0, sizeof(struct cfg_ptr));
	switch(e->type) {
	case CFG_TYPE_OPTION:
		ptr->o = cfg_to_option(e);
		goto fill_option;
	case CFG_TYPE_SECTION:
		ptr->s = cfg_to_section(e);
		goto fill_section;
	case CFG_TYPE_PACKAGE:
		ptr->p = cfg_to_package(e);
		goto fill_package;
	default:
		CFG_THROW(ctx, CFG_ERR_INVAL);
	}

fill_option:
	ptr->option = ptr->o->e.name;
	ptr->s = ptr->o->section;
fill_section:
	ptr->section = ptr->s->e.name;
	ptr->p = ptr->s->package;
fill_package:
	ptr->package = ptr->p->e.name;

	ptr->flags |= CFG_LOOKUP_DONE;

	return 0;
}



/*
 * verify that the end of the line or command is reached.
 * throw an error if extra arguments are given on the command line
 */
static void assert_eol(struct cfg_context *ctx, char **str)
{
	char *tmp;

	skip_whitespace(ctx, str);
	tmp = next_arg(ctx, str, false, false);
	if (*tmp && (ctx->flags & CFG_FLAG_STRICT))
		cfg_parse_error(ctx, *str, "too many arguments");
}

/*
 * switch to a different config, either triggered by cfg_load, or by a
 * 'package <...>' statement in the import file
 */
static void cfg_switch_config(struct cfg_context *ctx)
{
	struct cfg_parse_context *pctx;
	struct cfg_element *e;
	const char *name;

	pctx = ctx->pctx;
	name = pctx->name;

	/* add the last config to main config file list */
	if (pctx->package) {
		pctx->package->backend = ctx->backend;
		cfg_list_add(&ctx->root, &pctx->package->e.list);

		pctx->package = NULL;
		pctx->section = NULL;
	}

	if (!name)
		return;

	/*
	 * if an older config under the same name exists, unload it
	 * ignore errors here, e.g. if the config was not found
	 */
	e = cfg_lookup_list(&ctx->root, name);
	if (e)
		CFG_THROW(ctx, CFG_ERR_DUPLICATE);
	pctx->package = cfg_alloc_package(ctx, name);
}

/*
 * parse the 'package' cfg command (next config package)
 */
static void cfg_parse_package(struct cfg_context *ctx, char **str, bool single)
{
	char *name = NULL;

	/* command string null-terminated by strtok */
	*str += strlen(*str) + 1;

	name = next_arg(ctx, str, true, true);
	assert_eol(ctx, str);
	if (single)
		return;

	ctx->pctx->name = name;
	cfg_switch_config(ctx);
}

/*
 * parse the 'config' cfg command (open a section)
 */
static void cfg_parse_config(struct cfg_context *ctx, char **str)
{
	struct cfg_parse_context *pctx = ctx->pctx;
	struct cfg_element *e;
	struct cfg_ptr ptr;
	char *name = NULL;
	char *type = NULL;

	cfg_fixup_section(ctx, ctx->pctx->section);
	if (!ctx->pctx->package) {
		if (!ctx->pctx->name)
			cfg_parse_error(ctx, *str, "attempting to import a file without a package name");

		cfg_switch_config(ctx);
	}

	/* command string null-terminated by strtok */
	*str += strlen(*str) + 1;

	type = next_arg(ctx, str, true, false);
	if (!cfg_validate_type(type))
		cfg_parse_error(ctx, type, "invalid character in field");
	name = next_arg(ctx, str, false, true);
	assert_eol(ctx, str);

	if (!name || !name[0]) {
		ctx->internal = !pctx->merge;
		CFG_NESTED(cfg_add_section, ctx, pctx->package, type, &pctx->section);
	} else {
		cfg_fill_ptr(ctx, &ptr, &pctx->package->e);
		e = cfg_lookup_list(&pctx->package->sections, name);
		if (e)
			ptr.s = cfg_to_section(e);
		ptr.section = name;
		ptr.value = type;

		ctx->internal = !pctx->merge;
		CFG_NESTED(cfg_set, ctx, &ptr);
		pctx->section = cfg_to_section(ptr.last);
	}
}

/*
 * parse the 'option' cfg command (open a value)
 */
static void cfg_parse_option(struct cfg_context *ctx, char **str, bool list)
{
	struct cfg_parse_context *pctx = ctx->pctx;
	struct cfg_element *e;
	struct cfg_ptr ptr;
	char *name = NULL;
	char *value = NULL;

	if (!pctx->section)
		cfg_parse_error(ctx, *str, "option/list command found before the first section");

	/* command string null-terminated by strtok */
	*str += strlen(*str) + 1;

	name = next_arg(ctx, str, true, true);
	value = next_arg(ctx, str, false, false);
	assert_eol(ctx, str);

	cfg_fill_ptr(ctx, &ptr, &pctx->section->e);
	e = cfg_lookup_list(&pctx->section->options, name);
	if (e)
		ptr.o = cfg_to_option(e);
	ptr.option = name;
	ptr.value = value;

	ctx->internal = !pctx->merge;
	if (list)
		CFG_NESTED(cfg_add_list, ctx, &ptr);
	else
		CFG_NESTED(cfg_set, ctx, &ptr);
}

/*
 * parse a complete input line, split up combined commands by ';'
 */
static void cfg_parse_line(struct cfg_context *ctx, bool single)
{
	struct cfg_parse_context *pctx = ctx->pctx;
	char *word, *brk;

	word = pctx->buf;
	do {
		brk = NULL;
		word = strtok_r(word, " \t", &brk);
		if (!word)
			return;

		switch(word[0]) {
			case 0:
			case '#':
				return;
			case 'p':
				if ((word[1] == 0) || !strcmp(word + 1, "ackage"))
					cfg_parse_package(ctx, &word, single);
				else
					goto invalid;
				break;
			case 'c':
				if ((word[1] == 0) || !strcmp(word + 1, "onfig"))
					cfg_parse_config(ctx, &word);
				else
					goto invalid;
				break;
			case 'o':
				if ((word[1] == 0) || !strcmp(word + 1, "ption"))
					cfg_parse_option(ctx, &word, false);
				else
					goto invalid;
				break;
			case 'l':
				if ((word[1] == 0) || !strcmp(word + 1, "ist"))
					cfg_parse_option(ctx, &word, true);
				else
					goto invalid;
				break;
			default:
				goto invalid;
		}
		continue;
invalid:
		cfg_parse_error(ctx, word, "invalid command");
	} while (1);
}

/* max number of characters that escaping adds to the string */
#define CFG_QUOTE_ESCAPE	"'\\''"

/*
 * escape an cfg string for export
 */
static const char *cfg_escape(struct cfg_context *ctx, const char *str)
{
	const char *end;
	int ofs = 0;

	if (!ctx->buf) {
		ctx->bufsz = LINEBUF;
		ctx->buf = malloc(LINEBUF);

		if (!ctx->buf)
			return str;
	}

	while (1) {
		int len;

		end = strchr(str, '\'');
		if (!end)
			end = str + strlen(str);
		len = end - str;

		/* make sure that we have enough room in the buffer */
		while (ofs + len + sizeof(CFG_QUOTE_ESCAPE) + 1 > ctx->bufsz) {
			ctx->bufsz *= 2;
			ctx->buf = cfg_realloc(ctx, ctx->buf, ctx->bufsz);
		}

		/* copy the string until the character before the quote */
		memcpy(&ctx->buf[ofs], str, len);
		ofs += len;

		/* end of string? return the buffer */
		if (*end == 0)
			break;

		memcpy(&ctx->buf[ofs], CFG_QUOTE_ESCAPE, sizeof(CFG_QUOTE_ESCAPE));
		ofs += strlen(&ctx->buf[ofs]);
		str = end + 1;
	}

	ctx->buf[ofs] = 0;
	return ctx->buf;
}

/*
 * export a single config package to a file stream
 */
static void cfg_export_package(struct cfg_package *p, FILE *stream, bool header)
{
	struct cfg_context *ctx = p->ctx;
	struct cfg_element *s, *o, *i;

	if (header)
		fprintf(stream, "package %s\n", cfg_escape(ctx, p->e.name));
	cfg_foreach_element(&p->sections, s) {
		struct cfg_section *sec = cfg_to_section(s);
		fprintf(stream, "\nconfig %s", cfg_escape(ctx, sec->type));
		if (!sec->anonymous || (ctx->flags & CFG_FLAG_EXPORT_NAME))
			fprintf(stream, " '%s'", cfg_escape(ctx, sec->e.name));
		fprintf(stream, "\n");
		cfg_foreach_element(&sec->options, o) {
			struct cfg_option *opt = cfg_to_option(o);
			switch(opt->type) {
			case CFG_TYPE_STRING:
				fprintf(stream, "\toption %s", cfg_escape(ctx, opt->e.name));
				fprintf(stream, " '%s'\n", cfg_escape(ctx, opt->v.string));
				break;
			case CFG_TYPE_LIST:
				cfg_foreach_element(&opt->v.list, i) {
					fprintf(stream, "\tlist %s", cfg_escape(ctx, opt->e.name));
					fprintf(stream, " '%s'\n", cfg_escape(ctx, i->name));
				}
				break;
			default:
				fprintf(stream, "\t# unknown type for option '%s'\n", cfg_escape(ctx, opt->e.name));
				break;
			}
		}
	}
	fprintf(stream, "\n");
}

int cfg_export(struct cfg_context *ctx, FILE *stream, struct cfg_package *package, bool header)
{
	struct cfg_element *e;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, stream != NULL);

	if (package)
		cfg_export_package(package, stream, header);
	else {
		cfg_foreach_element(&ctx->root, e) {
			cfg_export_package(cfg_to_package(e), stream, header);
		}
	}

	return 0;
}

int cfg_import(struct cfg_context *ctx, FILE *stream, const char *name, struct cfg_package **package, bool single)
{
	struct cfg_parse_context *pctx;
	CFG_HANDLE_ERR(ctx);

	/* make sure no memory from previous parse attempts is leaked */
	cfg_cleanup(ctx);

	cfg_alloc_parse_context(ctx);
	pctx = ctx->pctx;
	pctx->file = stream;
	if (package && *package && single) {
		pctx->package = *package;
		pctx->merge = true;
	}

	/*
	 * If 'name' was supplied, assume that the supplied stream does not contain
	 * the appropriate 'package <name>' string to specify the config name
	 * NB: the config file can still override the package name
	 */
	if (name) {
		CFG_ASSERT(ctx, cfg_validate_package(name));
		pctx->name = name;
	}

	while (!feof(pctx->file)) {
		cfg_getln(ctx, 0);
		CFG_TRAP_SAVE(ctx, error);
		if (pctx->buf[0])
			cfg_parse_line(ctx, single);
		CFG_TRAP_RESTORE(ctx);
		continue;
error:
		if (ctx->flags & CFG_FLAG_PERROR)
			cfg_perror(ctx, NULL);
		if ((ctx->err != CFG_ERR_PARSE) ||
			(ctx->flags & CFG_FLAG_STRICT))
			CFG_THROW(ctx, ctx->err);
	}

	cfg_fixup_section(ctx, ctx->pctx->section);
	if (!pctx->package && name)
		cfg_switch_config(ctx);
	if (package)
		*package = pctx->package;
	if (pctx->merge)
		pctx->package = NULL;

	pctx->name = NULL;
	cfg_switch_config(ctx);

	/* no error happened, we can get rid of the parser context now */
	cfg_cleanup(ctx);

	return 0;
}


static char *cfg_config_path(struct cfg_context *ctx, const char *name)
{
	char *filename;

	CFG_ASSERT(ctx, cfg_validate_package(name));
	filename = cfg_malloc(ctx, strlen(name) + strlen(ctx->confdir) + 2);
	sprintf(filename, "%s/%s", ctx->confdir, name);

	return filename;
}

static void cfg_file_commit(struct cfg_context *ctx, struct cfg_package **package, bool overwrite)
{
	struct cfg_package *p = *package;
	FILE *f1, *f2 = NULL;
	char *name = NULL;
	char *path = NULL;
	char *filename = NULL;
	struct stat statbuf;
	bool do_rename = false;

	if (!p->path) {
		if (overwrite)
			p->path = cfg_config_path(ctx, p->e.name);
		else
			CFG_THROW(ctx, CFG_ERR_INVAL);
	}

	if ((asprintf(&filename, "%s/.%s.cfg-XXXXXX", ctx->confdir, p->e.name) < 0) || !filename)
		CFG_THROW(ctx, CFG_ERR_MEM);

	if (!mktemp(filename))
		*filename = 0;

	if (!*filename) {
		free(filename);
		CFG_THROW(ctx, CFG_ERR_IO);
	}

	if ((stat(filename, &statbuf) == 0) && ((statbuf.st_mode & S_IFMT) != S_IFREG))
		CFG_THROW(ctx, CFG_ERR_IO);

	/* open the config file for writing now, so that it is locked */
	f1 = cfg_open_stream(ctx, p->path, NULL, SEEK_SET, true, true);

	/* flush unsaved changes and reload from delta file */
	CFG_TRAP_SAVE(ctx, done);
	if (p->has_delta) {
		if (!overwrite) {
			name = cfg_strdup(ctx, p->e.name);
			path = cfg_strdup(ctx, p->path);
			/* dump our own changes to the delta file */
			if (!cfg_list_empty(&p->delta))
				CFG_INTERNAL(cfg_save, ctx, p);

			/*
			 * other processes might have modified the config
			 * as well. dump and reload
			 */
			cfg_free_package(&p);
			cfg_cleanup(ctx);
			CFG_INTERNAL(cfg_import, ctx, f1, name, &p, true);

			p->path = path;
			p->has_delta = true;
			*package = p;

			/* freed together with the cfg_package */
			path = NULL;
		}

		/* flush delta */
		if (!cfg_load_delta(ctx, p, true))
			goto done;
	}

	f2 = cfg_open_stream(ctx, filename, p->path, SEEK_SET, true, true);
	cfg_export(ctx, f2, p, false);

	fflush(f2);
	fsync(fileno(f2));
	cfg_close_stream(f2);

	do_rename = true;

	CFG_TRAP_RESTORE(ctx);

done:
	free(name);
	free(path);
	cfg_close_stream(f1);
	if (do_rename && rename(filename, p->path)) {
		unlink(filename);
		CFG_THROW(ctx, CFG_ERR_IO);
	}
	free(filename);
	sync();
	if (ctx->err)
		CFG_THROW(ctx, ctx->err);
}


/*
 * This function returns the filename by returning the string
 * after the last '/' character. By checking for a non-'\0'
 * character afterwards, directories are ignored (glob marks
 * those with a trailing '/'
 */
static inline char *get_filename(char *path)
{
	char *p;

	p = strrchr(path, '/');
	p++;
	if (!*p)
		return NULL;
	return p;
}

static char **cfg_list_config_files(struct cfg_context *ctx)
{
	char **configs;
	glob_t globbuf;
	int size, i;
	char *buf;
	char *dir;

	dir = cfg_malloc(ctx, strlen(ctx->confdir) + 1 + sizeof("/*"));
	sprintf(dir, "%s/*", ctx->confdir);
	if (glob(dir, GLOB_MARK, NULL, &globbuf) != 0) {
		free(dir);
		CFG_THROW(ctx, CFG_ERR_NOTFOUND);
	}

	size = sizeof(char *) * (globbuf.gl_pathc + 1);
	for(i = 0; i < globbuf.gl_pathc; i++) {
		char *p;

		p = get_filename(globbuf.gl_pathv[i]);
		if (!p)
			continue;

		size += strlen(p) + 1;
	}

	configs = cfg_malloc(ctx, size);
	buf = (char *) &configs[globbuf.gl_pathc + 1];
	for(i = 0; i < globbuf.gl_pathc; i++) {
		char *p;

		p = get_filename(globbuf.gl_pathv[i]);
		if (!p)
			continue;

		if (!cfg_validate_package(p))
			continue;

		configs[i] = buf;
		strcpy(buf, p);
		buf += strlen(buf) + 1;
	}
	free(dir);
	globfree(&globbuf);
	return configs;
}

static struct cfg_package *cfg_file_load(struct cfg_context *ctx, const char *name)
{
	struct cfg_package *package = NULL;
	char *filename;
	bool confdir;
	FILE *file = NULL;

	switch (name[0]) {
	case '.':
		/* relative path outside of /etc/config */
		if (name[1] != '/')
			CFG_THROW(ctx, CFG_ERR_NOTFOUND);
		/* fall through */
	case '/':
		/* absolute path outside of /etc/config */
		filename = cfg_strdup(ctx, name);
		name = strrchr(name, '/') + 1;
		confdir = false;
		break;
	default:
		/* config in /etc/config */
		filename = cfg_config_path(ctx, name);
		confdir = true;
		break;
	}

	CFG_TRAP_SAVE(ctx, done);
	file = cfg_open_stream(ctx, filename, NULL, SEEK_SET, false, false);
	ctx->err = 0;
	CFG_INTERNAL(cfg_import, ctx, file, name, &package, true);
	CFG_TRAP_RESTORE(ctx);

	if (package) {
		package->path = filename;
		package->has_delta = confdir;
		cfg_load_delta(ctx, package, false);
	}

done:
	cfg_close_stream(file);
	if (ctx->err) {
		free(filename);
		CFG_THROW(ctx, ctx->err);
	}
	return package;
}

__private CFG_BACKEND(cfg_file_backend, "file",
	.load = cfg_file_load,
	.commit = cfg_file_commit,
	.list_configs = cfg_list_config_files,
);
