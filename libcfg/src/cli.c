/*
 * cli - Command Line Interface for the Unified Configuration Interface
 * Copyright (C) 2008 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "cfg.h"

#define MAX_ARGS	4 /* max command line arguments for batch mode */

static const char *delimiter = " ";
static const char *appname;
static enum {
	CLI_FLAG_MERGE =    (1 << 0),
	CLI_FLAG_QUIET =    (1 << 1),
	CLI_FLAG_NOCOMMIT = (1 << 2),
	CLI_FLAG_BATCH =    (1 << 3),
	CLI_FLAG_SHOW_EXT = (1 << 4),
} flags;

static FILE *input;

static struct cfg_context *ctx;
enum {
	/* section cmds */
	CMD_GET,
	CMD_SET,
	CMD_ADD_LIST,
	CMD_DEL_LIST,
	CMD_DEL,
	CMD_RENAME,
	CMD_REVERT,
	CMD_REORDER,
	/* package cmds */
	CMD_SHOW,
	CMD_CHANGES,
	CMD_EXPORT,
	CMD_COMMIT,
	/* other cmds */
	CMD_ADD,
	CMD_IMPORT,
	CMD_HELP,
};

struct cfg_type_list {
	unsigned int idx;
	const char *name;
	struct cfg_type_list *next;
};

static struct cfg_type_list *type_list = NULL;
static char *typestr = NULL;
static const char *cur_section_ref = NULL;

static int cfg_cmd(int argc, char **argv);

static void
cfg_reset_typelist(void)
{
	struct cfg_type_list *type;
	while (type_list != NULL) {
			type = type_list;
			type_list = type_list->next;
			free(type);
	}
	if (typestr) {
		free(typestr);
		typestr = NULL;
	}
	cur_section_ref = NULL;
}

static char *
cfg_lookup_section_ref(struct cfg_section *s)
{
	struct cfg_type_list *ti = type_list;
	int maxlen;

	if (!s->anonymous || !(flags & CLI_FLAG_SHOW_EXT))
		return s->e.name;

	/* look up in section type list */
	while (ti) {
		if (strcmp(ti->name, s->type) == 0)
			break;
		ti = ti->next;
	}
	if (!ti) {
		ti = malloc(sizeof(struct cfg_type_list));
		if (!ti)
			return NULL;
		memset(ti, 0, sizeof(struct cfg_type_list));
		ti->next = type_list;
		type_list = ti;
		ti->name = s->type;
	}

	maxlen = strlen(s->type) + 1 + 2 + 10;
	if (!typestr) {
		typestr = malloc(maxlen);
	} else {
		typestr = realloc(typestr, maxlen);
	}

	if (typestr)
		sprintf(typestr, "@%s[%d]", ti->name, ti->idx);

	ti->idx++;

	return typestr;
}

static void cfg_usage(void)
{
	fprintf(stderr,
		"Usage: %s [<options>] <command> [<arguments>]\n\n"
		"Commands:\n"
		"\tbatch\n"
		"\texport     [<config>]\n"
		"\timport     [<config>]\n"
		"\tchanges    [<config>]\n"
		"\tcommit     [<config>]\n"
		"\tadd        <config> <section-type>\n"
		"\tadd_list   <config>.<section>.<option>=<string>\n"
		"\tdel_list   <config>.<section>.<option>=<string>\n"
		"\tshow       [<config>[.<section>[.<option>]]]\n"
		"\tget        <config>.<section>[.<option>]\n"
		"\tset        <config>.<section>[.<option>]=<value>\n"
		"\tdelete     <config>[.<section>[[.<option>][=<id>]]]\n"
		"\trename     <config>.<section>[.<option>]=<name>\n"
		"\trevert     <config>[.<section>[.<option>]]\n"
		"\trevert     <config>[.<section>[.<option>]]\n"
		"\tsave       [force] Save running configuration to flash\n"
		"\trestore    Restore flash configuration to running"
		"\n"
		"Options:\n"
		"\t-c <path>  set the search path for config files (default: /etc/config)\n"
		"\t-d <str>   set the delimiter for list values in cfg show\n"
		"\t-f <file>  use <file> as input instead of stdin\n"
		"\t-m         when importing, merge data into an existing package\n"
		"\t-n         name unnamed sections on export (default)\n"
		"\t-N         don't name unnamed sections\n"
		"\t-p <path>  add a search path for config change files\n"
		"\t-P <path>  add a search path for config change files and use as default\n"
		"\t-q         quiet mode (don't print error messages)\n"
		"\t-s         force strict mode (stop on parser errors, default)\n"
		"\t-S         disable strict mode\n"
		"\t-X         do not use extended syntax on 'show'\n"
		"\n",
		appname
	);
}

static void cli_perror(void)
{
	if (flags & CLI_FLAG_QUIET)
		return;

	cfg_perror(ctx, appname);
}

static void cfg_show_value(struct cfg_option *o)
{
	struct cfg_element *e;
	bool sep = false;

	switch(o->type) {
	case CFG_TYPE_STRING:
		printf("%s\n", o->v.string);
		break;
	case CFG_TYPE_LIST:
		cfg_foreach_element(&o->v.list, e) {
			printf("%s%s", (sep ? delimiter : ""), e->name);
			sep = true;
		}
		printf("\n");
		break;
	default:
		printf("<unknown>\n");
		break;
	}
}

static void cfg_show_option(struct cfg_option *o)
{
	printf("%s.%s.%s=",
		o->section->package->e.name,
		(cur_section_ref ? cur_section_ref : o->section->e.name),
		o->e.name);
	cfg_show_value(o);
}

static void cfg_show_section(struct cfg_section *s)
{
	struct cfg_element *e;
	const char *cname;
	const char *sname;

	cname = s->package->e.name;
	sname = (cur_section_ref ? cur_section_ref : s->e.name);
	printf("%s.%s=%s\n", cname, sname, s->type);
	cfg_foreach_element(&s->options, e) {
		cfg_show_option(cfg_to_option(e));
	}
}

static void cfg_show_package(struct cfg_package *p)
{
	struct cfg_element *e;

	cfg_reset_typelist();
	cfg_foreach_element( &p->sections, e) {
		struct cfg_section *s = cfg_to_section(e);
		cur_section_ref = cfg_lookup_section_ref(s);
		cfg_show_section(s);
	}
	cfg_reset_typelist();
}

static void cfg_show_changes(struct cfg_package *p)
{
	struct cfg_element *e;

	cfg_foreach_element(&p->saved_delta, e) {
		struct cfg_delta *h = cfg_to_delta(e);
		char *prefix = "";
		char *op = "=";

		switch(h->cmd) {
		case CFG_CMD_REMOVE:
			prefix = "-";
			break;
		case CFG_CMD_LIST_ADD:
			op = "+=";
			break;
		case CFG_CMD_LIST_DEL:
			op = "-=";
			break;
		default:
			break;
		}
		printf("%s%s.%s", prefix, p->e.name, h->section);
		if (e->name)
			printf(".%s", e->name);
		if (h->cmd != CFG_CMD_REMOVE)
			printf("%s%s", op, h->value);
		printf("\n");
	}
}

static int package_cmd(int cmd, char *tuple)
{
	struct cfg_element *e = NULL;
	struct cfg_ptr ptr;
	int ret = 0;

	if (cfg_lookup_ptr(ctx, &ptr, tuple, true) != CFG_OK) {
		cli_perror();
		return 1;
	}

	e = ptr.last;
	switch(cmd) {
	case CMD_CHANGES:
		cfg_show_changes(ptr.p);
		break;
	case CMD_COMMIT:
		if (flags & CLI_FLAG_NOCOMMIT)
			return 0;
		if (cfg_commit(ctx, &ptr.p, false) != CFG_OK) {
			cli_perror();
			ret = 1;
		}
		break;
	case CMD_EXPORT:
		cfg_export(ctx, stdout, ptr.p, true);
		break;
	case CMD_SHOW:
		if (!(ptr.flags & CFG_LOOKUP_COMPLETE)) {
			ctx->err = CFG_ERR_NOTFOUND;
			cli_perror();
			ret = 1;
		}
		switch(e->type) {
			case CFG_TYPE_PACKAGE:
				cfg_show_package(ptr.p);
				break;
			case CFG_TYPE_SECTION:
				cfg_show_section(ptr.s);
				break;
			case CFG_TYPE_OPTION:
				cfg_show_option(ptr.o);
				break;
			default:
				/* should not happen */
				return 1;
		}
		break;
	}

	if (ptr.p)
		cfg_unload(ctx, ptr.p);
	return ret;
}

static int cfg_do_import(int argc, char **argv)
{
	struct cfg_package *package = NULL;
	char *name = NULL;
	int ret = CFG_OK;
	bool merge = false;

	if (argc > 2)
		return 255;

	if (argc == 2)
		name = argv[1];
	else if (flags & CLI_FLAG_MERGE)
		/* need a package to merge */
		return 255;

	if (flags & CLI_FLAG_MERGE) {
		if (cfg_load(ctx, name, &package) != CFG_OK)
			package = NULL;
		else
			merge = true;
	}
	ret = cfg_import(ctx, input, name, &package, (name != NULL));
	if (ret == CFG_OK) {
		if (merge) {
			ret = cfg_save(ctx, package);
		} else {
			struct cfg_element *e;
			/* loop through all config sections and overwrite existing data */
			cfg_foreach_element(&ctx->root, e) {
				struct cfg_package *p = cfg_to_package(e);
				ret = cfg_commit(ctx, &p, true);
			}
		}
	}

	if (ret != CFG_OK) {
		cli_perror();
		return 1;
	}

	return 0;
}

static int cfg_do_package_cmd(int cmd, int argc, char **argv)
{
	char **configs = NULL;
	char **p;

	if (argc > 2)
		return 255;

	if (argc == 2)
		return package_cmd(cmd, argv[1]);

	if ((cfg_list_configs(ctx, &configs) != CFG_OK) || !configs) {
		cli_perror();
		return 1;
	}

	for (p = configs; *p; p++) {
		package_cmd(cmd, *p);
	}

	return 0;
}

static int cfg_do_add(int argc, char **argv)
{
	struct cfg_package *p = NULL;
	struct cfg_section *s = NULL;
	int ret;

	if (argc != 3)
		return 255;

	ret = cfg_load(ctx, argv[1], &p);
	if (ret != CFG_OK)
		goto done;

	ret = cfg_add_section(ctx, p, argv[2], &s);
	if (ret != CFG_OK)
		goto done;

	ret = cfg_save(ctx, p);

done:
	if (ret != CFG_OK)
		cli_perror();
	else if (s)
		fprintf(stdout, "%s\n", s->e.name);

	return ret;
}

static int cfg_do_section_cmd(int cmd, int argc, char **argv)
{
	struct cfg_element *e;
	struct cfg_ptr ptr;
	int ret = CFG_OK;
	int dummy;

	if (argc != 2)
		return 255;

	if (cfg_lookup_ptr(ctx, &ptr, argv[1], true) != CFG_OK) {
		cli_perror();
		return 1;
	}

	if (ptr.value && (cmd != CMD_SET) && (cmd != CMD_DEL) &&
	    (cmd != CMD_ADD_LIST) && (cmd != CMD_DEL_LIST) &&
	    (cmd != CMD_RENAME) && (cmd != CMD_REORDER))
		return 1;

	e = ptr.last;
	switch(cmd) {
	case CMD_GET:
		if (!(ptr.flags & CFG_LOOKUP_COMPLETE)) {
			ctx->err = CFG_ERR_NOTFOUND;
			cli_perror();
			return 1;
		}
		switch(e->type) {
		case CFG_TYPE_SECTION:
			printf("%s\n", ptr.s->type);
			break;
		case CFG_TYPE_OPTION:
			cfg_show_value(ptr.o);
			break;
		default:
			break;
		}
		/* throw the value to stdout */
		break;
	case CMD_RENAME:
		ret = cfg_rename(ctx, &ptr);
		break;
	case CMD_REVERT:
		ret = cfg_revert(ctx, &ptr);
		break;
	case CMD_SET:
		ret = cfg_set(ctx, &ptr);
		break;
	case CMD_ADD_LIST:
		ret = cfg_add_list(ctx, &ptr);
		break;
	case CMD_DEL_LIST:
		ret = cfg_del_list(ctx, &ptr);
		break;
	case CMD_REORDER:
		if (!ptr.s || !ptr.value) {
			ctx->err = CFG_ERR_NOTFOUND;
			cli_perror();
			return 1;
		}
		ret = cfg_reorder_section(ctx, ptr.s, strtoul(ptr.value, NULL, 10));
		break;
	case CMD_DEL:
		if (ptr.value && !sscanf(ptr.value, "%d", &dummy))
			return 1;
		ret = cfg_delete(ctx, &ptr);
		break;
	}

	/* no save necessary for get */
	if ((cmd == CMD_GET) || (cmd == CMD_REVERT))
		return 0;

	/* save changes, but don't commit them yet */
	if (ret == CFG_OK)
		ret = cfg_save(ctx, ptr.p);

	if (ret != CFG_OK) {
		cli_perror();
		return 1;
	}

	return 0;
}

static int cfg_batch_cmd(void)
{
	char *argv[MAX_ARGS + 2];
	char *str = NULL;
	int ret = 0;
	int i, j;

	for(i = 0; i <= MAX_ARGS; i++) {
		if (i == MAX_ARGS) {
			fprintf(stderr, "Too many arguments\n");
			return 1;
		}
		argv[i] = NULL;
		if ((ret = cfg_parse_argument(ctx, input, &str, &argv[i])) != CFG_OK) {
			cli_perror();
			i = 0;
			break;
		}
		if (!argv[i][0])
			break;
		argv[i] = strdup(argv[i]);
		if (!argv[i]) {
			perror("cfg");
			return 1;
		}
	}
	argv[i] = NULL;

	if (i > 0) {
		if (!strcasecmp(argv[0], "exit"))
			return 254;
		ret = cfg_cmd(i, argv);
	} else
		return 0;

	for (j = 0; j < i; j++) {
		free(argv[j]);
	}

	return ret;
}

static int cfg_batch(void)
{
	int ret = 0;

	flags |= CLI_FLAG_BATCH;
	while (!feof(input)) {
		struct cfg_element *e, *tmp;

		ret = cfg_batch_cmd();
		if (ret == 254)
			return 0;
		else if (ret == 255)
			fprintf(stderr, "Unknown command\n");

		/* clean up */
		cfg_foreach_element_safe(&ctx->root, tmp, e) {
			cfg_unload(ctx, cfg_to_package(e));
		}
	}
	flags &= ~CLI_FLAG_BATCH;

	return 0;
}

static int cfg_cmd(int argc, char **argv)
{
	int cmd = 0;

	if (!strcasecmp(argv[0], "batch") && !(flags & CLI_FLAG_BATCH))
		return cfg_batch();
	else if (!strcasecmp(argv[0], "show"))
		cmd = CMD_SHOW;
	else if (!strcasecmp(argv[0], "changes"))
		cmd = CMD_CHANGES;
	else if (!strcasecmp(argv[0], "export"))
		cmd = CMD_EXPORT;
	else if (!strcasecmp(argv[0], "commit"))
		cmd = CMD_COMMIT;
	else if (!strcasecmp(argv[0], "get"))
		cmd = CMD_GET;
	else if (!strcasecmp(argv[0], "set"))
		cmd = CMD_SET;
	else if (!strcasecmp(argv[0], "ren") ||
	         !strcasecmp(argv[0], "rename"))
		cmd = CMD_RENAME;
	else if (!strcasecmp(argv[0], "revert"))
		cmd = CMD_REVERT;
	else if (!strcasecmp(argv[0], "reorder"))
		cmd = CMD_REORDER;
	else if (!strcasecmp(argv[0], "del") ||
	         !strcasecmp(argv[0], "delete"))
		cmd = CMD_DEL;
	else if (!strcasecmp(argv[0], "import"))
		cmd = CMD_IMPORT;
	else if (!strcasecmp(argv[0], "help"))
		cmd = CMD_HELP;
	else if (!strcasecmp(argv[0], "add"))
		cmd = CMD_ADD;
	else if (!strcasecmp(argv[0], "add_list"))
		cmd = CMD_ADD_LIST;
	else if (!strcasecmp(argv[0], "del_list"))
		cmd = CMD_DEL_LIST;
	else
		cmd = -1;

	switch(cmd) {
		case CMD_ADD_LIST:
		case CMD_DEL_LIST:
		case CMD_GET:
		case CMD_SET:
		case CMD_DEL:
		case CMD_RENAME:
		case CMD_REVERT:
		case CMD_REORDER:
			return cfg_do_section_cmd(cmd, argc, argv);
		case CMD_SHOW:
		case CMD_EXPORT:
		case CMD_COMMIT:
		case CMD_CHANGES:
			return cfg_do_package_cmd(cmd, argc, argv);
		case CMD_IMPORT:
			return cfg_do_import(argc, argv);
		case CMD_ADD:
			return cfg_do_add(argc, argv);
		case CMD_HELP:
			cfg_usage();
			return 0;
		default:
			return 255;
	}
}

int main(int argc, char **argv)
{
	int ret;
	int c;

	flags = CLI_FLAG_SHOW_EXT;
	appname = argv[0];
	input = stdin;

    // begin: add by chenxiaojie to hook save, restore command
    if (argc >= 2) {
        if (strcmp(argv[1], "save") == 0) {
            if (argc == 3 && strcmp(argv[2], "force") == 0) {
                return cfg_save_all(1);
            }
            else {
                return cfg_save_all(0);
            }
        }
        else if (strcmp(argv[1], "restore") == 0) {
            return cfg_restore();
        }
        // otherwise, fall through to original process
    }
    // end: add by chenxiaojie to hook save, restore command
	ctx = cfg_alloc_context();
	if (!ctx) {
		fprintf(stderr, "Out of memory\n");
		return 1;
	}

	while((c = getopt(argc, argv, "c:d:f:LmnNp:P:sSqX")) != -1) {
		switch(c) {
			case 'c':
				cfg_set_confdir(ctx, optarg);
				break;
			case 'd':
				delimiter = optarg;
				break;
			case 'f':
				if (input != stdin) {
					perror("cfg");
					return 1;
				}

				input = fopen(optarg, "r");
				if (!input) {
					perror("cfg");
					return 1;
				}
				break;
			case 'm':
				flags |= CLI_FLAG_MERGE;
				break;
			case 's':
				ctx->flags |= CFG_FLAG_STRICT;
				break;
			case 'S':
				ctx->flags &= ~CFG_FLAG_STRICT;
				ctx->flags |= CFG_FLAG_PERROR;
				break;
			case 'n':
				ctx->flags |= CFG_FLAG_EXPORT_NAME;
				break;
			case 'N':
				ctx->flags &= ~CFG_FLAG_EXPORT_NAME;
				break;
			case 'p':
				cfg_add_delta_path(ctx, optarg);
				break;
			case 'P':
				cfg_add_delta_path(ctx, ctx->savedir);
				cfg_set_savedir(ctx, optarg);
				flags |= CLI_FLAG_NOCOMMIT;
				break;
			case 'q':
				flags |= CLI_FLAG_QUIET;
				break;
			case 'X':
				flags &= ~CLI_FLAG_SHOW_EXT;
				break;
			default:
				cfg_usage();
				return 0;
		}
	}
	if (optind > 1)
		argv[optind - 1] = argv[0];
	argv += optind - 1;
	argc -= optind - 1;

	if (argc < 2) {
		cfg_usage();
		return 0;
	}

	ret = cfg_cmd(argc - 1, argv + 1);
	if (input != stdin)
		fclose(input);

	if (ret == 255)
		cfg_usage();

	cfg_free_context(ctx);

	return ret;
}
