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
 * This file contains some common code for the cfg library
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <glob.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>	
#include <ctype.h>
#include "cfg.h"
/* added by lsz for oem */
#include "json/json_util.h"
#include "json/bits.h"
#include "json/arraylist.h"
/* added by lsz, end */

//#include "wmac/wmac.h"

static const char *cfg_errstr[] = {
	[CFG_OK] =            "Success",
	[CFG_ERR_MEM] =       "Out of memory",
	[CFG_ERR_INVAL] =     "Invalid argument",
	[CFG_ERR_NOTFOUND] =  "Entry not found",
	[CFG_ERR_IO] =        "I/O error",
	[CFG_ERR_PARSE] =     "Parse error",
	[CFG_ERR_DUPLICATE] = "Duplicate entry",
	[CFG_ERR_UNKNOWN] =   "Unknown error",
};

#include "cfg_internal.h"
#include "list.c"

__private const char *cfg_confdir = CFG_CONFDIR;
__private const char *cfg_savedir = CFG_SAVEDIR;

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#endif

/* exported functions */
struct cfg_context *cfg_alloc_context(void)
{
	struct cfg_context *ctx;

	ctx = (struct cfg_context *) malloc(sizeof(struct cfg_context));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(struct cfg_context));
	cfg_list_init(&ctx->root);
	cfg_list_init(&ctx->delta_path);
	cfg_list_init(&ctx->backends);
	ctx->flags = CFG_FLAG_STRICT | CFG_FLAG_SAVED_DELTA;

	ctx->confdir = (char *) cfg_confdir;
	ctx->savedir = (char *) cfg_savedir;

	cfg_list_add(&ctx->backends, &cfg_file_backend.e.list);
	ctx->backend = &cfg_file_backend;

	return ctx;
}

void cfg_free_context(struct cfg_context *ctx)
{
	struct cfg_element *e, *tmp;

	if (ctx->confdir != cfg_confdir)
		free(ctx->confdir);
	if (ctx->savedir != cfg_savedir)
		free(ctx->savedir);

	cfg_cleanup(ctx);
	CFG_TRAP_SAVE(ctx, ignore);
	cfg_foreach_element_safe(&ctx->root, tmp, e) {
		struct cfg_package *p = cfg_to_package(e);
		cfg_free_package(&p);
	}
	cfg_foreach_element_safe(&ctx->delta_path, tmp, e) {
		cfg_free_element(e);
	}
	CFG_TRAP_RESTORE(ctx);
	free(ctx);

ignore:
	return;
}

int cfg_set_confdir(struct cfg_context *ctx, const char *dir)
{
	char *cdir;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, dir != NULL);

	cdir = cfg_strdup(ctx, dir);
	if (ctx->confdir != cfg_confdir)
		free(ctx->confdir);
	ctx->confdir = cdir;
	return 0;
}

__private void cfg_cleanup(struct cfg_context *ctx)
{
	struct cfg_parse_context *pctx;

	if (ctx->buf) {
		free(ctx->buf);
		ctx->buf = NULL;
		ctx->bufsz = 0;
	}

	pctx = ctx->pctx;
	if (!pctx)
		return;

	ctx->pctx = NULL;
	if (pctx->package)
		cfg_free_package(&pctx->package);

	if (pctx->buf)
		free(pctx->buf);

	free(pctx);
}

void
cfg_perror(struct cfg_context *ctx, const char *str)
{
	cfg_get_errorstr(ctx, NULL, str);
}

void
cfg_get_errorstr(struct cfg_context *ctx, char **dest, const char *prefix)
{
	static char error_info[128];
	int err;
	const char *format =
		"%s%s" /* prefix */
		"%s%s" /* function */
		"%s" /* error */
		"%s"; /* details */

	error_info[0] = 0;

	if (!ctx)
		err = CFG_ERR_INVAL;
	else
		err = ctx->err;

	if ((err < 0) || (err >= CFG_ERR_LAST))
		err = CFG_ERR_UNKNOWN;

	switch (err) {
	case CFG_ERR_PARSE:
		if (ctx->pctx) {
			snprintf(error_info, sizeof(error_info) - 1, " (%s) at line %d, byte %d", (ctx->pctx->reason ? ctx->pctx->reason : "unknown"), ctx->pctx->line, ctx->pctx->byte);
			break;
		}
		break;
	default:
		break;
	}
	if (dest) {
		err = asprintf(dest, format,
			(prefix ? prefix : ""), (prefix ? ": " : ""),
			(ctx && ctx->func ? ctx->func : ""), (ctx && ctx->func ? ": " : ""),
			cfg_errstr[err],
			error_info);
		if (err < 0)
			*dest = NULL;
	} else {
		strcat(error_info, "\n");
		fprintf(stderr, format,
			(prefix ? prefix : ""), (prefix ? ": " : ""),
			(ctx && ctx->func ? ctx->func : ""), (ctx && ctx->func ? ": " : ""),
			cfg_errstr[err],
			error_info);
	}
}

int cfg_list_configs(struct cfg_context *ctx, char ***list)
{
	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, list != NULL);
	CFG_ASSERT(ctx, ctx->backend && ctx->backend->list_configs);
	*list = ctx->backend->list_configs(ctx);
	return 0;
}

int cfg_commit(struct cfg_context *ctx, struct cfg_package **package, bool overwrite)
{
	struct cfg_package *p;
	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, package != NULL);
	p = *package;
	CFG_ASSERT(ctx, p != NULL);
	CFG_ASSERT(ctx, p->backend && p->backend->commit);
	p->backend->commit(ctx, package, overwrite);
	return 0;
}

int cfg_load(struct cfg_context *ctx, const char *name, struct cfg_package **package)
{
	struct cfg_package *p;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, ctx->backend && ctx->backend->load);
	p = ctx->backend->load(ctx, name);
	if (package)
		*package = p;

	return 0;
}

int cfg_set_backend(struct cfg_context *ctx, const char *name)
{
	struct cfg_element *e;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, name != NULL);
	e = cfg_lookup_list(&ctx->backends, name);
	if (!e)
		CFG_THROW(ctx, CFG_ERR_NOTFOUND);
	ctx->backend = cfg_to_backend(e);
	return 0;
}

#define     LOCK_NAME   "/tmp/cfg_lock"

#if 0
#define DEBUG(...)       fprintf(stdout, ##__VA_ARGS__)
#else
#define DEBUG(...)
#endif

static void cfg_unlock(int fd)
{
    struct flock    lock;
    int     ret;

    lock.l_type = F_UNLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    ret = fcntl(fd, F_SETLKW, &lock);

    if (ret == -1) {
        DEBUG("Failed to unlock: %d %s\n", errno, strerror(errno));
    }

    close(fd);
    unlink(LOCK_NAME);
    return ;
}

static int cfg_lock(int wr)
{
    int     fd, ret;
    struct flock    lock;

    fd = open(LOCK_NAME, O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        DEBUG("Failed to create %s\n", LOCK_NAME);
        return -1;
    }

    lock.l_type = wr ? F_WRLCK : F_RDLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    ret = fcntl(fd, F_SETLKW, &lock);
    if (ret == -1) {
        DEBUG("Failed to set lock: %d %s\n", errno, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}
static int cfg_read_lock(void)
{
    return cfg_lock(0);
}
static int cfg_write_lock(void)
{
    return cfg_lock(1);
}
int cfg_visit_row(const char * tuple, 
        int (*visitor)(int /* row */, struct cfg_section *, void *), 
        void * arg)
{
    char * name;
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    int     ret = 0;
    int i = 0, lock;

    if (visitor == NULL || tuple == NULL) {
        return -EINVAL;
    }
    name = strdupa(tuple);
    if (name == NULL) {
        return -ENOMEM;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }

    lock = cfg_read_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }
    if (!(ptr.flags & CFG_LOOKUP_COMPLETE)) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_unlock(lock);

    {
        struct cfg_element *e;
        struct cfg_package *p = ptr.p;

        cfg_foreach_element(&p->sections, e) {
            struct cfg_section *s = cfg_to_section(e);
            ++i;
            ret = visitor(i, s, arg);
            if (ret <= 0) {
                cfg_free_context(ctx);
                return ret;
            }
        }
    }

    cfg_free_context(ctx);

    return ret;
}

int cfg_visit_package(const char * tuple, 
        int (*visitor)(struct cfg_package *, void *),
        void * arg)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    int     ret = 0, lock;
    char * name;

    if (visitor == NULL || tuple == NULL) {
        return -EINVAL;
    }
    name = strdupa(tuple);
    if (name == NULL) {
        return -ENOMEM;
    }

    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }

    lock = cfg_read_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }

    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }
    if (!(ptr.flags & CFG_LOOKUP_COMPLETE)) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }
    /*
     * all contents are loaded and  can release lock here,
     * so in @visitor class of writer, such as cfg_set_value can be used
     */
    cfg_unlock(lock);

    ret = visitor(ptr.p, arg);

    cfg_free_context(ctx);

    return ret;
}

int cfg_set_value(const char * table, 
        const char * id, const char * field, const char * value)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char    name[512];
    int lock;

    if (table == NULL || id == NULL || field == NULL || value == NULL) {
        return -EINVAL;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
   
    sprintf(name, "%s.%s.%s=%s", table, id, field, value);
    lock = cfg_write_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_set(ctx, &ptr);

    cfg_commit(ctx, &ptr.p, false);

    cfg_unlock(lock);

    cfg_free_context(ctx);

    cfg_update_notice();
    return 0;
}

// obsolute method
#if 0
int cfg_set_value_lockless(const char * table, 
        const char * id, const char * field, const char * value)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char    name[128];

    if (table == NULL || id == NULL) {
        return -EINVAL;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    
    sprintf(name, "%s.%s.%s=%s", table, id, field, value);
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_free_context(ctx);
        return -1;
    }

    cfg_set(ctx, &ptr);

    cfg_commit(ctx, &ptr.p, false);

    cfg_free_context(ctx);

    return 0;
}
#endif

int cfg_add_row(const char * table, 
        const char * id)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char    name[128];
    int lock;

    if (table == NULL || id == NULL) {
        return -EINVAL;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    
    sprintf(name, "%s.%s=%s", table, id, id);
    lock = cfg_write_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_set(ctx, &ptr);

    cfg_commit(ctx, &ptr.p, false);

    cfg_unlock(lock);
    cfg_free_context(ctx);
    return 0;
}

int cfg_del_item(const char * table, const char * id, const char * field)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char    name[128];
    int lock;

    if (table == NULL || id == NULL) {
        return -EINVAL;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    
    sprintf(name, "%s.%s.%s", table, id, field);
    lock = cfg_write_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_delete(ctx, &ptr);

    cfg_commit(ctx, &ptr.p, false);
    cfg_unlock(lock);

    cfg_free_context(ctx);

    cfg_update_notice();
    return 0;
}
int cfg_del_row(const char * table, 
        const char * id)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char    name[128];
    int lock;

    if (table == NULL || id == NULL) {
        return -EINVAL;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    
    sprintf(name, "%s.%s", table, id);
    lock = cfg_write_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_delete(ctx, &ptr);

    cfg_commit(ctx, &ptr.p, false);
    cfg_unlock(lock);

    cfg_free_context(ctx);
    return 0;
}

#define DEFAULT_DIR "/default"

int cfg_get_default_value(const char * table, const char * id, 
        const char * field, char * value, int length)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char   name[128];

    if (table == NULL || id == NULL || field == NULL || value == NULL) {
        return -EINVAL;
    }
    sprintf(name, "%s.%s.%s", table, id, field);

    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    cfg_set_confdir(ctx, DEFAULT_DIR);
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_free_context(ctx);
        return -1;
    }
    if (!(ptr.flags & CFG_LOOKUP_COMPLETE)) {
        cfg_free_context(ctx);
        return -1;
    }

    if (ptr.o->type == CFG_TYPE_STRING) {
        strncpy(value, ptr.o->v.string, length - 1);
        value[length - 1] = 0;
        cfg_free_context(ctx);
        return 0;
    }
    else {
        cfg_free_context(ctx);
        return -1;
    }
}
int cfg_get_value(const char * table, const char * id, 
        const char * field, char * value, int length)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char   name[128];
    int lock;

    if (table == NULL || id == NULL || field == NULL || value == NULL) {
        return -EINVAL;
    }
    sprintf(name, "%s.%s.%s", table, id, field);

    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    lock = cfg_read_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }
    if (!(ptr.flags & CFG_LOOKUP_COMPLETE)) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    if (ptr.o->type == CFG_TYPE_STRING) {
        strncpy(value, ptr.o->v.string, length - 1);
        value[length - 1] = 0;
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return 0;
    }
    else {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }
}
int cfg_reset_module(const char * module)
{
    char    file[128];
    int lock;

    sprintf(file, "/default/%s", module);
    lock = cfg_write_lock();
    if (lock == -1) {
        return -1;
    }
    if (access(file, R_OK) ==  0) {
        sprintf(file, "cp /default/%s %s/%s 2>/dev/null", module, CFG_CONFDIR, module);
        system(file);
    }
    else {
        sprintf(file, "%s/%s", CFG_CONFDIR, module);
        truncate(file, 0);
    }

    cfg_unlock(lock);

    cfg_update_notice();
    return 0;
}
int cfg_truncate_module(const char * module)
{
    char    file[128];
    int     lock, ret;
    
    lock = cfg_write_lock();
    if (lock == -1) {
        return -1;
    }
    sprintf(file, "%s/%s", CFG_CONFDIR, module);
    ret = truncate(file, 0);
    cfg_unlock(lock);

    return ret;
}

int cfg_add_list_value(const char * table, 
        const char * id, const char * field, const char * value)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char    name[128];
    int     lock;

    if (table == NULL || id == NULL) {
        return -EINVAL;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    
    sprintf(name, "%s.%s.%s=%s", table, id, field, value);
    lock = cfg_write_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_add_list(ctx, &ptr);

    strcpy(name, table);
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_commit(ctx, &ptr.p, false);
    cfg_unlock(lock);

    cfg_free_context(ctx);

    cfg_update_notice();
    return 0;
}
int cfg_del_list_value(const char * table, 
        const char * id, const char * field, const char * value)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char    name[128];
    int lock;

    if (table == NULL || id == NULL) {
        return -EINVAL;
    }
    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    
    sprintf(name, "%s.%s.%s=%s", table, id, field, value);
    lock = cfg_write_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_del_list(ctx, &ptr);

    strcpy(name, table);
    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_unlock(lock);
        cfg_free_context(ctx);
        return -1;
    }

    cfg_commit(ctx, &ptr.p, false);
    cfg_unlock(lock);

    cfg_free_context(ctx);

    cfg_update_notice();
    return 0;
}

#define SPEC_DIR    "/default/spec"
#define SPEC_MODULE "spec"
#define SPEC_SECTION    "spec"

int cfg_get_spec(const char * module)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char   name[128];
    int     value;

    if (module == NULL) {
        return -EINVAL;
    }
    sprintf(name, "%s.%s.%s", SPEC_MODULE, SPEC_SECTION, module);

    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    cfg_set_confdir(ctx, SPEC_DIR);

    if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
        cfg_free_context(ctx);
        return -1;
    }
    if (!(ptr.flags & CFG_LOOKUP_COMPLETE)) {
        cfg_free_context(ctx);
        return -1;
    }

    if (ptr.o->type == CFG_TYPE_STRING) {
        value = atoi(ptr.o->v.string);
        if (value < 0) {
            value = 0;
        }
        cfg_free_context(ctx);
        return value;
    }
    else {
        cfg_free_context(ctx);
        return 0;
    }
}

#define CFG_FLASH_CFG_DIR   "/etc/flash_cfg"

/*
 * return value:
 *  @detect:        1 for detect OK
 *  @restore:       0 for restore OK
 *  @save:          0 for save OK
 */
struct cfg_perment {
    const char * id;
    int (*detect)(void);
    int (*restore)(void);
    int (*save)(int /* force */);   // force: regradless no difference when true
};

#define CFG_TARGZ_FILE      "cfg.tar.bz2"
#define CFG_TARGZ_MD5_FILE      "cfg.tar.bz2.md5sum"

static int cfg_tarbz2_detect(void)
{
    char    file[128], path[256];
    int     ret;
   
    getcwd(path, sizeof(path));
    chdir(CFG_FLASH_CFG_DIR); 
    sprintf(file, "%s/%s", CFG_FLASH_CFG_DIR, CFG_TARGZ_FILE);
    if (access(file, R_OK) !=  0) {
        DEBUG("Cfg file is not exited!\n");
        chdir(path);
        return 0;
    }
    sprintf(file, "%s/%s", CFG_FLASH_CFG_DIR, CFG_TARGZ_MD5_FILE);
    if (access(file, R_OK) !=  0) {
        DEBUG("Cfg md5 file is not exited!\n");
        chdir(path);
        return 0;
    }

    sprintf(file, "md5sum -s -c %s", CFG_TARGZ_MD5_FILE);
    DEBUG("Running command: %s\n", file);
    ret = system(file);

    chdir(path);
    if (ret == 0) {
        return 1;
    }
    else {
        return 0;
    }
}

static int cfg_tarbz2_restore(void)
{
    char    cmd[128];

    sprintf(cmd, "tar xjvf %s/%s -C %s", CFG_FLASH_CFG_DIR, CFG_TARGZ_FILE, 
            CFG_CONFDIR);
    DEBUG("Running command: %s\n", cmd);

    return system(cmd);
}
#define TMP_DIR "/tmp"
static void cfg_tarbz2_cleanup(void)
{
    char    buf[128];

    sprintf(buf, "%s/%s", TMP_DIR, CFG_TARGZ_FILE);
    unlink(buf);
    sprintf(buf, "%s/%s", TMP_DIR, CFG_TARGZ_MD5_FILE);
    unlink(buf);
}
static int cfg_tarbz2_save(int force)
{
    char    buf[128], file[64];;
    int     ret;
    char    path[256];

    cfg_tarbz2_cleanup();

    getcwd(path, sizeof(path));
    chdir(CFG_CONFDIR);

    sprintf(file, "%s/%s", TMP_DIR, CFG_TARGZ_FILE);
    sprintf(buf, "tar cjvf %s *", file);
    DEBUG("Running command: %s\n", buf);
    ret = system(buf);
    if (ret) {
        DEBUG("Tar file failed!\n");
        ret = -1;
        goto out;
    }
    chmod(file, 0666);
    chdir(TMP_DIR);
    sprintf(buf, "md5sum %s > %s", CFG_TARGZ_FILE, 
            CFG_TARGZ_MD5_FILE);
    DEBUG("Running command: %s\n", buf);
    ret = system(buf);
    if (ret) {
        DEBUG("MD5 sum file failed!\n");
        ret = -1;
        goto out;
    }
    chmod(CFG_TARGZ_MD5_FILE, 0666);

    if (!force) {   // compare md5 file
        sprintf(buf, "diff %s/%s %s/%s", CFG_FLASH_CFG_DIR, CFG_TARGZ_MD5_FILE, 
                TMP_DIR, CFG_TARGZ_MD5_FILE);
        ret = system(buf);
        DEBUG("Running command: %s\n with result: %d\n", buf, ret);
        if (ret == 0) {
            DEBUG("No different, nothing to do!\n");
            goto out;
        }
    }
    sprintf(buf, "cp %s/%s %s", TMP_DIR, CFG_TARGZ_FILE, CFG_FLASH_CFG_DIR);
    ret = system(buf);
    if (ret) {
        DEBUG("COPY tar file failed!\n");
        ret = -1;
        goto out;
    }

    sprintf(buf, "cp %s/%s %s", TMP_DIR, CFG_TARGZ_MD5_FILE, CFG_FLASH_CFG_DIR);
    ret = system(buf);
    if (ret) {
        DEBUG("COPY tar file failed!\n");
        ret = -1;
        goto out;
    }
    ret = 0;

    DEBUG("Save OK!\n");
out:
    chdir(path);
    cfg_tarbz2_cleanup();
    return 0;
}

static struct cfg_perment cfg_supplicants[] = {
    {"tarbz2", cfg_tarbz2_detect, cfg_tarbz2_restore, cfg_tarbz2_save},
};

int cfg_restore()
{
    struct cfg_perment * suit;
    int i, lock, ret, status, fd;
    pid_t   pid;

    /* 
     * begin: add by chenxiaojie
     * nothing to do under fit mode
     * process zoomfitap will restore from nvram when running
     */
    if (cfg_get_device_mode() == DEVICE_MODE_FIT) {
        return 0;
    }
    /* end: add by chenxiaojie */

    for (i = 0; i < ARRAY_SIZE(cfg_supplicants); ++i) {
        suit = &cfg_supplicants[i];
        if (suit->detect()) {
            goto found;
        }
    }

    return -1;      // no supplicant suitable

found:
    lock = cfg_write_lock();
    if (lock == -1) {
        return -1;
    }
    pid = fork();
    if (pid == -1) {
        cfg_unlock(lock);
        return -1;
    }
    if (pid == 0) { // child process do the real work
        close(0);
        close(1);
        close(2);
        fd = open("/dev/null", O_RDWR | O_NOCTTY);
        dup(fd);
        dup(fd);

        ret = suit->restore();
        sync();
        exit(ret);
    }
    else {
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
        }
        else {
            ret = -1;
        }
    }
    cfg_unlock(lock);

    if (ret == 0) {
        cfg_update_notice();
    }
    
    return ret;
}

int cfg_save_all(int force)
{
    const char * default_supp = "tarbz2";
    int i, ret, fd, status;
    struct cfg_perment * suit;
    int lock;
    pid_t   pid;

    /*
     * begin: add by chenxiaojie
     * under fit mode, store the configs generated by nvram_set
     */
    if (cfg_get_device_mode() == DEVICE_MODE_FIT) {
        system("nvram s2n");
        return 0;
    }
    /* end: add by chenxiaojie */

    // Find suitable supplicant
    for (i = 0; i < ARRAY_SIZE(cfg_supplicants); ++i) {
        suit = &cfg_supplicants[i];
        if (strcmp(default_supp, suit->id) == 0) {
            goto found;
        }
    }

    return -1;

found:
    lock = cfg_write_lock();
    if (lock == -1) {
        DEBUG("Failed to get write lock!\n");
        return -1;
    }
    pid = fork();
    if (pid == -1) {
        cfg_unlock(lock);
        return -1;
    }
    if (pid == 0) { // child process do the real work
        close(0);
        close(1);
        close(2);
        fd = open("/dev/null", O_RDWR | O_NOCTTY);
        dup(fd);
        dup(fd);

        ret = suit->save(force);
        sync();
        exit(ret);
    }
    else {
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
        }
        else {
            ret = -1;
        }
    }
    cfg_unlock(lock);

    return ret;
}

int cfg_show_running_config(int fd)
{
    struct cfg_context * ctx;
    struct cfg_ptr ptr;
    char   name[128], buf[256];
    int lock, ret, len, rows;
    char ** configs = NULL;
    char ** p;
    struct cfg_package * package;
    struct cfg_element * es;
    struct cfg_element * e;

    ctx = cfg_alloc_context();
    if (ctx == NULL) {
        return -ENOMEM;
    }
    lock = cfg_read_lock();
    if (lock == -1) {
        cfg_free_context(ctx);
        return -1;
    }
    ret = -1;
    if ((cfg_list_configs(ctx, &configs) != CFG_OK) || !configs) {
        goto out;
    }

    for (p = configs; *p; ++p) {
        strcpy(name, *p);
        if (cfg_lookup_ptr(ctx, &ptr, name, true) != CFG_OK) {
            continue;
        }
        if (!(ptr.flags & CFG_LOOKUP_COMPLETE)) {
            goto out_free;
        }
        package = ptr.p;
        rows = 0;
        cfg_foreach_element(&package->sections, es) {
            struct cfg_section * s = cfg_to_section(es);
            cfg_foreach_element(&s->options, e) {
                struct cfg_option * o = cfg_to_option(e);

                ++rows;
                if (o->type != CFG_TYPE_LIST) {
                    len = sprintf(buf, "%s.%s.%s=%s\n", 
                            ptr.p->e.name, 
                            s->e.name, 
                            o->e.name, o->v.string);
                    write(fd, buf, len);
                }
                else {
                    struct cfg_element * e2;
                    int count = 0;
                    len = sprintf(buf, "%s.%s.%s=", 
                            ptr.p->e.name, 
                            s->e.name, 
                            o->e.name);
                    cfg_foreach_element(&o->v.list, e2) {
                        if (count == 0) {
                            len += sprintf(buf + len, "%s", e2->name);
                        }
                        else {
                            len += sprintf(buf + len, " %s", e2->name);
                        }
                        ++count;
                    }
                    len += sprintf(buf + len, "\n");
                    write(fd, buf, len);
                }
            }
        }
        if (rows) {
            write(fd, "\n", 1);
        }
    }

    ret = 0;

out_free:
    free(configs);
out:
    cfg_unlock(lock);
    cfg_free_context(ctx);
    return ret;
}

/* added by lsz for oem packages management */
static int iterate_cfg_set( struct json_object *cfg ) {
	const char *op, *table, *section, *option, *value;
	struct json_object *obj;
	obj = json_object_object_get( cfg, "op" );
	if ( obj != NULL && json_object_get_type(obj) == json_type_string ) {
		op = json_object_get_string( obj );
		if ( op[0] == 'a' ) {
			if ( !strcmp( op, "add_row" ) ) {
				obj = json_object_object_get( cfg, "tbl" );
				table = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "sect" );
				section = json_object_get_string(obj);
				if ( table != NULL && section != NULL ) {
					cfg_add_row( table, section );
				}
			} else if ( !strcmp( op, "add_list" ) ) {
				obj = json_object_object_get( cfg, "tbl" );
				table = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "sect" );
				section = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "opt" );
				option = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "val" );
				value = json_object_get_string(obj);
				if ( table != NULL && section != NULL && option != NULL && value != NULL  ) {
					cfg_add_list_value( table, section, option, value );
				}
			}
		} else if ( op[0] == 'd' ) {
			if ( !strcmp( op, "del" ) ) {
				obj = json_object_object_get( cfg, "tbl" );
				table = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "sect" );
				section = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "opt" );
				option = json_object_get_string(obj);
				if ( table != NULL && section != NULL && option != NULL  ) {
					cfg_del_item( table, section, option );
				}
			} else if ( !strcmp( op, "del_list" ) ) {
				obj = json_object_object_get( cfg, "tbl" );
				table = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "sect" );
				section = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "opt" );
				option = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "val" );
				value = json_object_get_string(obj);
				if ( table != NULL && section != NULL && option != NULL && value != NULL  ) {
					cfg_del_list_value( table, section, option, value );
				}
			} else if ( !strcmp( op, "del_row" ) ) {
				obj = json_object_object_get( cfg, "tbl" );
				table = json_object_get_string(obj);
				obj = json_object_object_get( cfg, "sect" );
				section = json_object_get_string(obj);
				if ( table != NULL && section != NULL ) {
					cfg_del_row( table, section );
				}
			}
		} else if ( !strcmp(op, "set") ) {
			obj = json_object_object_get( cfg, "tbl" );
			table = json_object_get_string(obj);
			obj = json_object_object_get( cfg, "sect" );
			section = json_object_get_string(obj);
			obj = json_object_object_get( cfg, "opt" );
			option = json_object_get_string(obj);
			obj = json_object_object_get( cfg, "val" );
			value = json_object_get_string(obj);
			if ( table != NULL && section != NULL && option != NULL && value != NULL  ) {
				cfg_set_value( table, section, option, value );
			}
		}
	}
	return 0;
}

static int oem_cfg_func_cfg_set( const char *key, struct json_object *rootObj ) {
	struct json_object *obj;
	struct array_list *cfg;
	int len, i;
	obj = json_object_object_get( rootObj, key );
	if ( obj != NULL && json_object_get_type(obj) == json_type_array) {
		cfg = json_object_get_array( obj );
		len = array_list_length(cfg);
		for ( i = 0; i < len; i++ ) {
			obj = array_list_get_idx( cfg, i );
			iterate_cfg_set( obj );
		}
	}
	return 0;
}

typedef struct {
	char *key;
	int (*fn)( const char *key, struct json_object *rootobj );
}oem_cfg_func; /* OEM */
static const oem_cfg_func oem_cfg_func_table[] = {
		{"cfg",				oem_cfg_func_cfg_set},
		{NULL,				NULL}
};

static int load_oem_default_config() {
	struct json_object *rootObj = NULL;
	int i, ret;

	DEBUG("load_oem_default_config, start.\n");

	rootObj = json_object_from_file( "/var/pkg_web/oem_info");
	if ( is_error(rootObj) ) {
		DEBUG( "Cannot find root object. Reason:%ld\n", (long)0 - (long)rootObj );
		return -1;
	} else {
		for ( i = 0; oem_cfg_func_table[i].key; i ++ ) {
			ret = oem_cfg_func_table[i].fn( oem_cfg_func_table[i].key, rootObj );
			if ( ret != 0 ) {
				json_object_put( rootObj );
				return -1;
			}
		}
	}

	DEBUG("load_oem_default_config, success.\n");
	json_object_put( rootObj );
	return 0;
}
/* added by lsz for oem packages management, end */

int cfg_reset_factory(void)
{
    char    buf[128];
    int     ret, lock;

    if (cfg_get_device_mode() == DEVICE_MODE_FIT) {
        unlink("/tmp/.nvram");  //TODO: find a nice way
        unlink(CFG_FLASH_CFG_DIR"/nvram");
        cfg_update_notice();
        return 0;
    }

    lock = cfg_write_lock();
    if (lock == -1) {
        DEBUG("Failed to remove old config!\n");
        return -1;
    }
    sprintf(buf, "rm -fr %s/*", CFG_CONFDIR);
    DEBUG("Running command: %s\n", buf);
    ret = system(buf);
    if (ret) {
        cfg_unlock(lock);
        DEBUG("Failed to remove old config!\n");
        return -1;
    }

    sprintf(buf, "cp /default/* %s/ 2>/dev/null", CFG_CONFDIR);
    DEBUG("Running command: %s\n", buf);
    ret = system(buf);
    if (ret < 0) {
        DEBUG("Failed to copy default config!\n");
        cfg_unlock(lock);
        return -1;
    }

	/* added by lsz for oem */
	ret = load_oem_default_config();
	if ( ret < 0 ) {
        DEBUG("Can't load customer config!\n");
	}
	/* added by lsz, end */

    cfg_unlock(lock);

    cfg_update_notice();
    return 0;
}

#define CFG_RUNNING_FILE       CFG_LOAD_FILE
#define CFG_RUNNING_MD5FILE    "running.md5"
#ifdef  CFG_LOAD_DIR
#undef  CFG_LOAD_DIR
#endif
#define CFG_LOAD_DIR           "cfg_load"
#define CFG_LOAD_TARGZ_FILE    "cfg_load.tar.bz2"
#define CFG_LOAD_CHECKFILE     "upload.cfg.tmp"
#define CFG_MD5SUM_CHECKFILE   "upload.md5.tmp"
#define CFG_VERSION_TAG        "#[version]"
#define CFG_MODULE_TAG         "#[module]"
#define CFG_MD5SUM_TAG         "#[md5sum]"
#define TAG_VALUE_INTVAL       2

static int cfg_create_config_file(const char *file)
{
    return open(file, O_CREAT | O_RDWR | O_TRUNC, 0600);
}

static int cfg_assemble_version(const char *file)
{
    char *version;
    struct product_info info;
    char buf[64], cmd[128];

    memset(&info, 0, sizeof(info));
    if (!cfg_get_product_info(&info)) {
        sprintf(buf, "%s %s", info.model, info.software_version);
    }
    else {
        sprintf(buf, "Commsky AP");
    }

    version = buf;
    
    sprintf(cmd, "echo \"%s-[%s]\" >> %s", CFG_VERSION_TAG, version, file);    
    
    return system(cmd);
}

static int cfg_assemble_filelist(const char *file)
{
    int i, num, ret;
    struct dirent ** namelist;
    char cmd[128];
    char path[256];

    getcwd(path, sizeof(path));
    chdir(CFG_CONFDIR);

    num = scandir(CFG_CONFDIR, &namelist, NULL, alphasort);
    for (i = 0; i < num; ++i) {
        if (namelist[i]->d_type != DT_REG 
                || strcmp(namelist[i]->d_name, ".") == 0 
                || strcmp(namelist[i]->d_name, "..") == 0) {
            free(namelist[i]);
            continue;
        }
        sprintf(cmd,"echo \"%s-[%s]\" >> %s", CFG_MODULE_TAG, namelist[i]->d_name,  file); 
        ret = system(cmd);
        if (ret) {
            DEBUG("Failed to echo module %s config file!\n", namelist[i]->d_name);
            free(namelist[i]);
            continue;
        }
        
        sprintf(cmd,"cat %s >> %s", namelist[i]->d_name,  file);
        ret = system(cmd);
        if (ret) {
            DEBUG("Failed to cat %s config file!\n", namelist[i]->d_name);
        }
        free(namelist[i]);
    }
    if (namelist) {
        free(namelist);
    }

    chdir(path);
    return 0;
}

int cfg_assemble_md5sum(const char *file)
{
    char md5file[64], cmd[128], buf[64];
    int ret, fd, num;

    sprintf(md5file, "%s/%s", TMP_DIR, CFG_RUNNING_MD5FILE);
    ret = creat(md5file, 0600);
    if (ret < 0) {
        DEBUG("Failed to create md5sum!\n");
        return -1;
    }

    sprintf(cmd, "md5sum %s >> %s", file, md5file);
    ret = system(cmd);
    if (ret < 0) {
        DEBUG("Failed to md5sum!\n");
        return -1;
    }

    fd = open(md5file, O_RDONLY, 0400);
    if (fd < 0) {
        DEBUG("Failed to open md5_file!\n");
        return -1;
    }
    do {
		num = read(fd, buf, 32);
	} while (num < 0 && errno == EINTR);
    buf[num] = 0;
    close(fd);
    
    sprintf(cmd,"echo \"%s-[%s]\" >> %s", CFG_MD5SUM_TAG, buf,  file);   
    ret = system(cmd);
    if (ret < 0) {
        DEBUG("Failed to echo ]!\n");
        return -1;
    }
    
    return 0; 
}

int cfg_upload_config(void)
{
    int ret, lock, fd;
    char file[64];
    
    lock = cfg_write_lock();
    if (lock < 0) {
        DEBUG("Failed to cfg_write_lock!\n");
        ret=lock;
        return -1;
    }

    sprintf(file, "%s/%s", TMP_DIR, CFG_RUNNING_FILE);
    fd = cfg_create_config_file(file);
    if (fd < 0) {
        DEBUG("Failed to creat cfgfile, %s %s!\n", file , strerror(errno));
        ret=fd;
        goto UNLOCK;
    }
    
    ret = cfg_assemble_version(file);
    if (ret) {
        DEBUG("Failed to accemb version!\n");
        goto UNLOCK;
    }

    ret = cfg_assemble_filelist(file);
    if (ret) {
        DEBUG("Failed to accemb version!\n");
        goto UNLOCK;
    }

    ret = cfg_assemble_md5sum(file);
    if (ret) {
        DEBUG("Failed to accemb version!\n");
        goto UNLOCK;
    }
    
UNLOCK:    
    cfg_unlock(lock);
    close(fd);
    
    return ret;
}

void cfg_upload_cleanup(void)
{
    char file[64];

    sprintf(file, "%s/%s", TMP_DIR, CFG_RUNNING_FILE);
    unlink(file);
    
    sprintf(file, "%s/%s", TMP_DIR, CFG_RUNNING_MD5FILE);
    unlink(file);
}

static FILE* cfg_open_config_file(char *file)
{
    return fopen(file, "r");
}

static int cfg_check_config_md5sum(FILE *fp)
{
    char cmd[128], line[256];
    char ch, *md5sum;
    int ret, cur, num, endpos;

    endpos = sizeof(line) - 1;
    num = 0;

    cur = ftell(fp);
    fseek(fp, 0L, SEEK_END);  
    while (1)
    {
        if (num >= endpos) {
            break;
        }
        if((ch = fgetc(fp)) != '\n')
        {
            num++;
            line[endpos - num] = ch;
            fseek(fp, -2L, SEEK_CUR);
        }
        else
        {
            break;
        }
    }
    fseek(fp, cur, SEEK_SET);
    
    md5sum = line + (endpos - num);
    if (strncmp(md5sum, CFG_MD5SUM_TAG, strlen(CFG_MD5SUM_TAG))) {
        DEBUG("Failed to compare with md5sum tag!\n");
        return -1;
    }
    
    md5sum += strlen(CFG_MD5SUM_TAG) + TAG_VALUE_INTVAL;
    md5sum[32] = 0;
    
    sprintf(cmd, "sed '$d' %s > %s", CFG_RUNNING_FILE, CFG_LOAD_CHECKFILE);
    ret = system(cmd); 
    if (ret) {
        DEBUG("Failed to create none-md5sum temp file!\n");
        return -1;
    }

    sprintf(cmd, "echo \"%s  %s/%s\" > %s", md5sum, TMP_DIR, CFG_LOAD_CHECKFILE, 
        CFG_MD5SUM_CHECKFILE);
    ret = system(cmd); 
    if (ret) {
        DEBUG("Failed to create md5sum temp file!\n");
        return -1;
    }

    sprintf(cmd, "md5sum -c %s > /dev/null 2>&1", CFG_MD5SUM_CHECKFILE);
    return system(cmd);
}

static int cfg_check_config_version(FILE *fp)
{
    struct product_info info;
    char version[32], line[256];
    int pos, cp = 0;
       
    if (fgets(line, sizeof(line), fp) == NULL) {
        DEBUG("Failed to fgets line!\n");
        return -1;
    }

    if (strncmp(line, CFG_VERSION_TAG, strlen(CFG_VERSION_TAG))) {
        DEBUG("Failed to compare with version tag!\n");
        return -1;
    }

    memset(version, 0, sizeof(version));
    pos = strlen(CFG_VERSION_TAG) +  TAG_VALUE_INTVAL; 
    while (line[pos] != ']' && pos < strlen(line) && cp < sizeof(version)) {
        version[cp++] = line[pos++];
    }

    /* TODO: Got version, how to check? */
    if (!cfg_get_product_info(&info)) {
        if (strncmp(version, info.model, strlen(info.model)) && 
            strncmp(version, info.production, strlen(info.production))) {
            return -1;
        }
    }
    
    return 0;
}

static int cfg_resolve_config_filelist(FILE *fp)
{
    FILE *fp_cfg = NULL;
    char module[64], line[256], path[256];;
    int pos, cp, ret;
    
    getcwd(path, sizeof(path));
    chdir(TMP_DIR);
    
    sprintf(line, "mkdir -p %s", CFG_LOAD_DIR);
    ret = system(line); 
    if (ret) {
        DEBUG("Failed to mkdir %s.!\n", CFG_LOAD_DIR);
        return -1;
    }
    
    chdir(CFG_LOAD_DIR);
    system("rm -f *");

    ret = 0;
    while (1) {
        memset(line, 0, sizeof(line));
        if (fgets(line, sizeof(line), fp) == NULL) {
            ret = -1;
            DEBUG("Failed to fgets line!\n");         
            break;
        }

        if (!strncmp(line, CFG_MODULE_TAG, strlen(CFG_MODULE_TAG))) {
            memset(module, 0, sizeof(module));
            cp = 0;
            pos = strlen(CFG_MODULE_TAG) +  TAG_VALUE_INTVAL; 
            while (line[pos] != ']' && pos < strlen(line) && cp < sizeof(module)) {
                module[cp++] = line[pos++];
            }

            if (fp_cfg) {
                fclose(fp_cfg);
            }
            fp_cfg = fopen(module, "w");
            if (!fp_cfg) {
                ret = -1;
                DEBUG("Failed to fopen:%s!\n", module);
                break;
            }
        }
        else if (!strncmp(line, CFG_MD5SUM_TAG, strlen(CFG_MD5SUM_TAG))) {
            break;
        }
        else if (fp_cfg == NULL){
            ret = -1;
            DEBUG("Failed to get fp!\n");
            break;
        }
        else {
            ret = fputs(line, fp_cfg);
            if (ret < 0) {
                DEBUG("Failed to fputs!\n");
                break;
            }
        }
    }

    if (fp_cfg) {
        fclose(fp_cfg);
    }

    chdir(CFG_CONFDIR);

    sprintf(module, "%s/%s", TMP_DIR, CFG_LOAD_TARGZ_FILE);
    sprintf(line, "tar cjvf %s * > /dev/null 2>&1", module);
    ret = system(line);
    if (ret) {
        DEBUG("Failed to tar file %s!\n", module);
        ret = -1;
        goto err;
    }

    sprintf(line, "rm -f *");
    ret = system(line);
    if (ret) {
        DEBUG("rm -f *!\n");
        ret = -1;
        goto err;
    }

    sprintf(line, "cp %s/%s/* ./", TMP_DIR, CFG_LOAD_DIR);
    ret = system(line);
    if (ret) {
        DEBUG("Failed to cp new cfg file in config dir!\n");
        ret = -1;
        goto err;
    }

    ret = cfg_save_all(0);
    if (ret) {
        DEBUG("Failed to cfg_save_all!\n");

        sprintf(line, "rm -f *");
        system(line);

        sprintf(line, "tar xjvf %s/%s -C %s > /dev/null 2>&1", 
            TMP_DIR, CFG_LOAD_TARGZ_FILE, CFG_CONFDIR);
        system(line);
    }

err:
    chdir(path);
    return ret;
}

int cfg_download_config(void)
{
    char path[256];
    FILE *fp = NULL;
    int ret, lock;
enum {
 CFG_DOWNLOAD_OPEN_FAIL=1,
 CFG_DOWNLOAD_LOCK_FAIL,
 CFG_DOWNLOAD_MD5_FAIL,
 CFG_DOWNLOAD_VERSION_FAIL,
 CFG_DOWNLOAD_WRITE_FAIL
};
    getcwd(path, sizeof(path));
    chdir(TMP_DIR);
    
    fp = cfg_open_config_file(CFG_RUNNING_FILE);
    if (!fp) {
        DEBUG("Failed to open config file!\n");
        ret = CFG_DOWNLOAD_OPEN_FAIL;
        goto CHDIR;
    }

    lock = cfg_read_lock();
    if (lock < 0) {
        DEBUG("Failed to cfg_write_lock!\n");
        ret = CFG_DOWNLOAD_LOCK_FAIL;
        goto CLOSEFILE;
    }   

    ret = cfg_check_config_md5sum(fp);
    if (ret) {
        DEBUG("Failed to check config file md5sum!\n");
        ret = CFG_DOWNLOAD_MD5_FAIL;
        goto UNLOCK;
    }

    ret = cfg_check_config_version(fp);
    if (ret) {
        DEBUG("Failed to check config file version!\n");
        ret = CFG_DOWNLOAD_VERSION_FAIL;
        goto UNLOCK;
    }

    ret = cfg_resolve_config_filelist(fp);
    if (ret) {
        DEBUG("Failed to resolve config file list!\n");
        ret = CFG_DOWNLOAD_WRITE_FAIL;
        goto UNLOCK;
    }

UNLOCK:
    cfg_unlock(lock);
CLOSEFILE:    
    fclose(fp);
CHDIR:
    chdir(path);
    return ret;
}

void cfg_dowanload_cleanup(void)
{
    char file[64];

    sprintf(file, "%s/%s", TMP_DIR, CFG_RUNNING_FILE);
    unlink(file);
    
    sprintf(file, "%s/%s", TMP_DIR, CFG_LOAD_CHECKFILE);
    unlink(file);
    
    sprintf(file, "%s/%s", TMP_DIR, CFG_MD5SUM_CHECKFILE);
    unlink(file);

    sprintf(file, "%s/%s", TMP_DIR, CFG_LOAD_TARGZ_FILE);
    unlink(file);

    sprintf(file, "rm -fr %s/%s", TMP_DIR, CFG_LOAD_DIR);
    system(file);
}

#undef TMP_DIR

#define MANUFILE    "/etc/manudata"
//#define BOOTLOADER_VERSION_KEY  "uboot_version"
//#define BOOTLOADER_BUILDTIME_KEY  "uboot_buildtime"
#define PRODUCT_SERIAL_KEY      "serial"
#define HARDWARE_VERSION_KEY    "hardware_version"
#define BOOT_MATCH_KEY          "match"

int cfg_get_env(const char * key, char * value, int size)
{
    FILE * fp;
    char    line[128];
    char *  sep;
    int     ret;
    char    ch;

    fp = fopen(MANUFILE, "r");
    if (fp == NULL) {
        return -1;
    }

    ret = -1;
    while (fgets(line, sizeof(line) - 1, fp) != NULL) {
        if (line[0] == 0) {
            continue;   // empty line
        }
        if (line[0] == '#') {
            continue;   /// comment line
        }
        sep = strchr(line, '=');
        if (sep == NULL) {
            continue;   // quird line
        }
        *sep = 0;
        if (strcmp(line, key) == 0) {
            ++sep;
            while ((ch = *sep) != 0) {
                if (ch == '\n' || ch == '\r') {
                    break;
                }
                *value = ch;
                --size;
                if (size == 0) {
                    break;
                }

                ++sep;
                ++value;
            }
            *value = 0;
            ret = 0;
#if 0
            strcpy(value, sep + 1);
            ret = 0;
#endif
            break;
        }
    }
    fclose(fp);
    return ret;
}
#ifndef BUILDTIME
#error Fix your makefile to define build time!
#endif
static unsigned long g_buildtime = BUILDTIME;

static int cfg_fetch_value(const char * line, const char * key, int len, 
        char * value)
{
    char * str;
    char ch;
    
    str = strstr(line, key);
    if (str == NULL) {
        return -1;
    }
    str += len;
    while ((ch = *str) != 0) {
        if (ch == ' ') {
            break;
        }
        *value = ch;
        ++str;
        ++value;
    }
    *value = 0;

    return 0;
}

/* added by lsz for oem package management */
int oem_sw_ver_map( char *outVer, const char *inVer ) {
#define MAX_SW_VER_ARGVS_NUM	4
	json_object *rootObj, *tmp, *argv, *obj, *tmp2;
	struct array_list *argvs;
	int r, carrybit, len, r_commsky, r_minus, n, i, ret;
	const char *fmt;
	int nArgvs[MAX_SW_VER_ARGVS_NUM], V;

	ret = sscanf(inVer, "V%dR%d", &V, &r_commsky );
	DEBUG("ret:%d, V:%d, r_commsky:%d\n", ret, V, r_commsky);

	rootObj = json_object_from_file( "/var/pkg_web/oem_info");
	if ( is_error(rootObj) ) {
		DEBUG( "Cannot find root object. Reason:%ld\n", (long)0 - (long)rootObj );
		return -1;
	} else {
		obj = json_object_object_get( rootObj, "sw_ver" );
		if ( obj != NULL && json_object_get_type(obj) == json_type_object ) {
			tmp = json_object_object_get( obj, "r" );
			if ( tmp != NULL && json_object_get_type(tmp) == json_type_int ) {
				r = json_object_get_int( tmp );
			}

			tmp = json_object_object_get( obj, "fmt" );
			if ( tmp != NULL && json_object_get_type(tmp) == json_type_string ) {
				fmt = json_object_get_string( tmp );
			}

			tmp = json_object_object_get( obj, "carrybit" );
			if ( tmp != NULL && json_object_get_type(tmp) == json_type_int ) {
				carrybit = json_object_get_int( tmp );
			}

			tmp = json_object_object_get( obj, "argvs" );
			if ( tmp != NULL && json_object_get_type(tmp) == json_type_array ) {
				argvs = json_object_get_array( tmp );
				len = array_list_length( argvs );
				for ( i = 0; i < len; i++ ) {
					argv = array_list_get_idx( argvs, i );
					if ( argv != NULL && json_object_get_type(argv) == json_type_object ) {
						tmp2 = json_object_object_get( argv, "val" );
						if ( tmp2!= NULL && json_object_get_type(tmp2) == json_type_int ) {
							nArgvs[i] = json_object_get_int( tmp2 );
							DEBUG("nArgvs[%d]:%d\n", i, nArgvs[i]);
						}
					}
				}
			}
			DEBUG( "r:%d, fmt:\"%s\", carrybit:%d\n", r, fmt, carrybit );

			r_minus = r_commsky - r;
			DEBUG("r_minus:%d\n", r_minus);
			if ( r_minus < 0 ) {
				r_minus = 0;
			} else if ( r_minus != 0 ) {
				nArgvs[len - 1] += r_minus;
				for ( i = len - 1; i >=0; i-- ) {
					if ( i != 0 ) {
						n = nArgvs[i] / carrybit;
//						DEBUG("\ni:%d n:%d, nArgvs[%d]:%d\n", i, n, i, nArgvs[i]);
//						DEBUG("before carry nArgvs[i-1]:%d\n", nArgvs[i -1]);
						nArgvs[i - 1] += n;
//						DEBUG("after carry nArgvs[i-1]:%d\n", nArgvs[i -1]);
//						DEBUG("after carry nArgvs[i] :%d \n", nArgvs[i]);
						nArgvs[i] -= (n * carrybit);
//						DEBUG("after carry nArgvs[i]:%d\n\n\n", nArgvs[i]);
					}
				}
			}

			switch ( len ) {
				case 0:
					strcpy( outVer, fmt );
					break;
				case 1:
					sprintf( outVer, fmt, nArgvs[0] );
					break;
				case 2:
					sprintf( outVer, fmt, nArgvs[0], nArgvs[1] );
					break;
				case 3:
					sprintf( outVer, fmt, nArgvs[0], nArgvs[1], nArgvs[2] );
					break;
				case 4:
					sprintf( outVer, fmt, nArgvs[0], nArgvs[1], nArgvs[2], nArgvs[3] );
					break;
				default:
					json_object_put( rootObj );
					return -1;
			}

		} else {
			json_object_put( rootObj );
			return -1;
		}
	}

	json_object_put( rootObj );
	return 0;
}
/* added by lsz for oem package management, end */

#define PRODUCT_MATCH_STRING_LENGTH     11
int cfg_get_product_info(struct product_info * info)
{
    char    value[512], tmp[32];
    int     ret;
    FILE *  fp;

    memset(info, 0, sizeof(*info));

    fp = fopen("/proc/cmdline", "r");
    if (fp == NULL) {
        return -1;
    }

    if (fgets(value, sizeof(value) - 1, fp) == NULL) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    ret = cfg_fetch_value(value, "buildtime", sizeof("buildtime"), tmp);
    if (ret) {
        info->bootloader_buildtime = 0;
    }
    else {
        info->bootloader_buildtime = (unsigned long)atol(tmp);
    }

    ret = cfg_fetch_value(value, "bootversion", sizeof("bootversion"), 
            info->bootloader_version);
    if (ret) {
        strcpy(info->bootloader_version, "Unknown");
    }
#if 0 
    ret = cfg_fetch_value(value, "softver", sizeof("softver"), 
            tmp);
    if (ret) {
        strcpy(info->software_version, "Unknown");
//        strcpy(info->production_match, "Unknown");
    }
    else {
        strcpy(info->software_version, tmp + PRODUCT_MATCH_STRING_LENGTH);
//        tmp[PRODUCT_MATCH_STRING_LENGTH] = 0;
//        strcpy(info->production_match, tmp);
    }
#endif

    ret = cfg_fetch_value(value, BOOT_MATCH_KEY, sizeof(BOOT_MATCH_KEY), info->production_match);
    if (ret) {
        strcpy(info->production_match, "Unknown");
    }

    info->software_buildtime = g_buildtime;

    ret = cfg_get_env(HARDWARE_VERSION_KEY, info->hardware_version, 
            sizeof(info->hardware_version));
    if (ret) {
        strcpy(info->hardware_version, "Unknown");
    }

    ret = cfg_get_env(PRODUCT_SERIAL_KEY, info->serial, 
            sizeof(info->serial));
    if (ret) {
        strcpy(info->serial, "Unknown");
    }

    ret = cfg_get_env(MAC_ENV, info->mac, sizeof(info->mac));
    if (ret) {
        strcpy(info->mac, "Unknown");
    }
#define _STR(x) #x
#define STR(x)  _STR(x)
    strcpy(info->company, "CommSky");
    ret = cfg_get_env(MODEL_ENV, info->model, sizeof(info->model));
    if (ret) {
        strcpy(info->model, STR(PRODUCT));
    }
    strcpy(info->production, STR(PRODUCT));  // defined in Makefile
   
    if (cfg_get_device_mode() == DEVICE_MODE_FAT) { 
		if ( oem_sw_ver_map( info->software_version, STR(SOFTVERSION) ) != 0 )
			strcpy(info->software_version, STR(SOFTVERSION));
        strcpy(info->software_inner_version, STR(SOFTVERSION_INNER));  // defined in Makefile
    }
    else {
        strcpy(info->software_version, STR(SOFTVERSION_FITAP));
        strcpy(info->software_inner_version, STR(SOFTVERSION_INNER_FITAP));  // defined in Makefile
    }

    return 0;
}

static int cfg_get_mtd_dev(const char *name, char *dev)
{
    char line[128], *endpos;
    FILE *  fp;

    fp = fopen("/proc/mtd", "r");
    if (fp == NULL) {
        return -1;
    }

again:
    if (fgets(line, sizeof(line) - 1, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    
    if (strstr(line, name) == NULL) {
        goto again;
    }
    else {
        memset(dev, 0, sizeof(*dev));
        endpos = strstr(line, ":");
        if (endpos == NULL) {
            fclose(fp);
            return -1;
        }
        strncpy(dev, line, endpos-line);
        dev[endpos-line] = 0;
    }
    
    fclose(fp);

    return 0;
}

static int cfg_get_upgrade_checkstr(const char *imagefile, char *checkstr)
{
    int ret = -1;
    FILE *  fp;
    image_header_t header;

    fp = fopen(imagefile, "r");
    if (fp == NULL) {
        DEBUG("Open image file %s failed!\n", imagefile);
        return -1;
    }

    do {
        ret = fread(&header, sizeof(image_header_t), 1, fp);
    } while(ret <= 0 && errno == EINTR);
    fclose(fp);

    if (ret <= 0) {
        DEBUG("Read image file %s header failed!\n", imagefile);
        return -1;
    }
        
    strcpy(checkstr, (char *)(header.ih_name));
    
    return 0;
}


#define UPGRADE_IMAGE_NAME  "upgradeimg"
#define CURRENT_IMAGE_NAME  "kernel"
/* it is the first img identically */
#define FIRST_UPIMG_MTD     "mtd3"
#define BOOT_FIRST_IMG      "firstimg"
#define BOOT_SECOND_IMG     "secondimg"
static int cfg_set_bootimage(const char *mtddev)
{
    char cmd[64];
    
    if (!strncmp(mtddev, FIRST_UPIMG_MTD, strlen(FIRST_UPIMG_MTD))) {
        sprintf(cmd, "fw_setenv bootimg %s", BOOT_FIRST_IMG);
        fprintf(stdout, "Step3: set boot from first image ");
    }
    else  {
        sprintf(cmd, "fw_setenv bootimg %s", BOOT_SECOND_IMG);
        fprintf(stdout, "Step3: set boot from second image ");
    }

    if (system(cmd) == 0) {
        fprintf(stdout, "ok\n");
        return 0;
    }
    else {
        fprintf(stdout, "failed \n");
        return -1;
    }
}

int cfg_upgrade_image(const char *imagefile)
{
    char cmd[128], mtddev[32], checkstr[64];
    int ret;

    ret = cfg_get_mtd_dev(UPGRADE_IMAGE_NAME, mtddev);
    if (ret) {
        DEBUG("Failed get mtd dev!\n");
        return MTDDEV_GET_FAILED;
    }

    ret = cfg_get_upgrade_checkstr(imagefile, checkstr);
    if (ret) {
        DEBUG("Failed get upgrde checkstr!\n");
        /* don't return even failed, actually check the imagefile information will get form 
         * image file header in upgrade, here is redundant 
         */
        // return -2;
        //strcpy(checkstr, "nothing");  /* cheat upgrade */
    }
    strcpy(checkstr, "nothing");  /* cheat upgrade . avoid wrong checkstr, e.g. string contains '\n' */

    sprintf(cmd, "upgrade -c %s", imagefile);
    ret = system(cmd);
    if (ret) {
        DEBUG("Check Upgrade file failed for %d!\n", ret);
        return VERSION_MATCH_FAILED; 
    }
   
#ifndef NO_STATUS_LED  
    system("echo 3 > /proc/config_led/config_status_led ");
#endif
    sprintf(cmd, "upgrade -m /dev/%s -n %s %s", mtddev, checkstr, imagefile);
    ret = system(cmd);
    if (ret) {
        DEBUG("Upgrade file failed for %d!\n", ret);
        return IMG_UPGRADE_FAILED; 
    }
#ifndef NO_STATUS_LED
    system("echo 2 > /proc/config_led/config_status_led ");
#endif

    ret = cfg_set_bootimage(mtddev);
    if (ret) {
        DEBUG("Set boot image failed!\n");
        return BOOTIMG_SET_FAILED;
    }
    
    return 0;
}

// return value: 0 for match
int cfg_compare_product_match(const char * str1, const char * str2)
{
    int i;

    for (i = 0; i < PRODUCT_MATCH_STRING_LENGTH; ++i) {
        if (str1[i] == '*' || str2[i] == '*') {
            continue;
        }

        if (str1[i] != str2[i]) {
            return str1[i] - str2[i];
        }

    }

    return 0;
}

int cfg_boot_from(void)
{
    char mtddev[16];
    int ret;
    
    ret = cfg_get_mtd_dev(UPGRADE_IMAGE_NAME, mtddev);
    
    if (ret) {
        DEBUG("Failed get mtd dev!\n");
        return -1;
    }

    if (!strncmp(mtddev, FIRST_UPIMG_MTD, strlen(FIRST_UPIMG_MTD))) {
        return 1;
    }
    else {
        return 0;
    }

}

int cfg_get_imgheader(int imgnum, image_header_t *header)
{ 
    int fd, bootnum, ret;
    char device[32], mtddev[16];

    bootnum = cfg_boot_from();
    if ((unsigned int)bootnum > 1 || (unsigned int)imgnum > 1) {
        DEBUG("Invalid imgnum, %d,%d!\n", bootnum, imgnum);
        return -1;
    }
    
    if (bootnum == imgnum) {
        ret = cfg_get_mtd_dev(CURRENT_IMAGE_NAME, mtddev);
    }
    else {
        ret = cfg_get_mtd_dev(UPGRADE_IMAGE_NAME, mtddev);
    }
    if (ret) {
        DEBUG("Get mtd device failed!\n");
        return -1;
    }
    
    sprintf(device, "/dev/%s", mtddev);
    
    fd = open(device, O_RDONLY);
	if (fd < 0 ) {
        DEBUG("Open device %s failed!\n", device);
        return -1;
    }
    if (read(fd, header, sizeof(image_header_t)) != sizeof(image_header_t)) {
        close(fd);
        DEBUG("Read image header failed!\n");
        return -1;
    }

    if (ntohl(header->ih_magic) != IH_MAGIC) {
        close(fd);
        DEBUG("Invalid magic number 0x%x!\n", header->ih_magic);
        return -1;
    }
    close(fd);
    /* Fix me: it's better to check the image file crc */
    return 0;   
}

int cfg_get_led_status(led_status_s *status, int num, led_product_e product)
{
#define LED_CONFIG_DIR  "/proc/config_led"    
    typedef struct {
        led_id_e id;
        char file[32];
    } led_file_s;

    led_file_s ledes_panel[] = {
        {LED_ID_POWER,  "config_power_led"},
        {LED_ID_WAN,    "Ethernet0-0"},
        {LED_ID_WLAN,   "config_wlan0_led"},
        {LED_ID_STATUS, "config_status_led"},
        {LED_ID_LAN1,   "Ethernet0-1"},
        {LED_ID_LAN2,   "Ethernet0-2"}
    };

    led_file_s ledes_11n[] = {
        {LED_ID_POWER,  "config_power_led"},
        {LED_ID_STATUS, "config_status_led"},
        {LED_ID_LAN,    "GigabitEthernet0-0"},
        {LED_ID_WLAN,   "config_wlan0_led"},
        {LED_ID_WLAN,   "config_wlan1_led"}
    };

    led_file_s ledes_wrt[] = {
        {LED_ID_POWER,  "config_power_led"},
        {LED_ID_WLAN,   "config_wlan0_led"},
        {LED_ID_WAN,    "Ethernet0-0"},
        {LED_ID_LAN,    "Ethernet1-0"},
        {LED_ID_LAN,    "Ethernet1-1"},
        {LED_ID_LAN,    "Ethernet1-2"},
        {LED_ID_LAN,    "Ethernet1-3"}
    };

    led_file_s ledes_11ac_in[] = {
        {LED_ID_RGB,   "config_rgb_led"}
    };

    led_file_s ledes_11ac_out[] = {
        {LED_ID_POWER,  "config_power_led"},
        {LED_ID_STATUS, "config_status_led"},
        {LED_ID_LAN,    "GigabitEthernet0-0"},
        {LED_ID_WLAN0,  "config_wlan0_led"},
        {LED_ID_WLAN1,  "config_wlan1_led"}
    };
    
    char path[64], line[16];
    int i, j;
    FILE *fp;
    led_state_e state;
    led_file_s *ledes = ledes_11n;
    int size = sizeof(ledes_11n)/sizeof(ledes_11n[0]);
        
    getcwd(path, sizeof(path));
    chdir(LED_CONFIG_DIR);

    switch (product) {
        case LED_PANEL_AP_e:
            ledes = ledes_panel;
            size = sizeof(ledes_panel)/sizeof(ledes_panel[0]);
            break;

        case LED_11n_AP35:
        case LED_11n_AP36:
            ledes = ledes_11n;
            size = sizeof(ledes_11n)/sizeof(ledes_11n[0]);
            break;

        case LED_11ac_AP_IN:
            ledes = ledes_11ac_in;
            size = sizeof(ledes_11ac_in)/sizeof(ledes_11ac_in[0]);
            break;
            
        case LED_11ac_AP_OUT:
            ledes = ledes_11ac_out;
            size = sizeof(ledes_11ac_out)/sizeof(ledes_11ac_out[0]);
            break;
            
        case LED_WRT_AP:
            ledes = ledes_wrt;
            size = sizeof(ledes_wrt)/sizeof(ledes_wrt[0]);
            break;

        default:
            size = 0;
            break;
    }
    
    for (i = 0; i < num; i++) {
        for (j = 0; j < size; j++) {
            if (status[i].id == ledes[j].id) {
                state = LED_STATE_INVALID;
                fp = fopen(ledes[j].file, "r");
                if (fp != NULL) {
                    if (fgets(line, sizeof(line) - 1, fp) != NULL) {
                        state = atoi(line);
                    }
                    fclose(fp);
                }
                if (status[i].state == LED_STATE_INVALID) {
                    status[i].state = state;
                }
                else if (state != LED_STATE_INVALID) {
                    if (state > status[i].state) {
                        status[i].state = state;
                    }
                }
            }
        }
    }

    chdir(path);    
    return 0;
}

int cfg_get_int(const char * table, const char * id, 
        const char * field, int * value)
{
    char    buf[32];
    int     ret;

    ret = cfg_get_value(table, id, field, buf, sizeof(buf));
    if (ret == 0) {
        *value = atoi(buf);
    }

    return ret;
}

int cfg_get_enable(const char * table, const char * id, 
        const char * field, int * enable)
{
    char    buf[32];
    int     ret;

    ret = cfg_get_value(table, id, field, buf, sizeof(buf));
    if (ret == 0) {
        if (strcmp(buf, "enabled") == 0) {
            *enable = 1;
        }
        else {
            *enable = 0;
        }
    }

    return ret;
}

//add by puyg: create tech_support for device file ,version file and dula image file
#if 0
int show_device_info(int fd){

    struct product_info product_info;
    int len = 0;
    char cmd[128] = {};

    cfg_get_product_info(&product_info);

    len = sprintf(cmd, "Device name: %s\r\n"
      "SN: %s\r\n"
      "Device MAC: %s\r\n"
      "Vendor: %s\r\n",
      product_info.model,
      product_info.serial,
      product_info.mac,
      product_info.company);
      
    write(fd, cmd, len);
    memset(cmd, 0, sizeof(cmd));
    
    return 0;
}

int show_version_info(int fd){
    struct product_info product_info;
    int len = 0;
    char *Dversion;
    char  t1[80], t2[80];
    char cmd[256] = {};

    cfg_get_product_info(&product_info);

    ctime_r((time_t *)&product_info.software_buildtime, t1);
    ctime_r((time_t *)&product_info.bootloader_buildtime, t2);

    len = sprintf(cmd,
      "Bootloader version: %s\r\n"
      "Software version: %s\r\n"
      "Hardware version: %s\r\n",
      product_info.bootloader_version,
      product_info.software_version,
      product_info.hardware_version);
    write(fd, cmd, len);
    memset(cmd, 0, sizeof(cmd));

    len = sprintf(cmd,
      "SN: %s\r\n"
      "Software build time: %s"
      "Bootloader build time: %s",
      product_info.serial,
      t1, t2);
    write(fd, cmd, len);
    memset(cmd, 0, sizeof(cmd));

    len = sprintf(cmd, "Software inner version: %s%s\n", 
            product_info.software_inner_version, Dversion);
    write(fd, cmd, len);
    memset(cmd, 0, sizeof(cmd));
    
    len = sprintf(cmd, "Production match string: %s\n", 
            product_info.production_match);
    write(fd, cmd, len);
    memset(cmd, 0, sizeof(cmd));

    return 0;
}

int show_dual_image_info(int fd){
    int ret, i;
    image_header_t header;
    time_t timestamp;
    char time_str[80];
    int len = 0;
    char cmd[128] = {};

    ret = cfg_boot_from();
    if (ret == 0) {
        len = sprintf(cmd, "System boot from: first image\r\n");
        write(fd, cmd, len);
        memset(cmd, 0, sizeof(cmd));
    }
    else if (ret == 1) {
        len = sprintf(cmd, "System boot from: second image\r\n");
        write(fd, cmd, len);
        memset(cmd, 0, sizeof(cmd));
    }
    else {
        len = sprintf(cmd, "System boot from: Unknow which image\r\n");
        write(fd, cmd, len);
        memset(cmd, 0, sizeof(cmd));
    }

    for (i = 0; i < 2; i++) {
        ret = cfg_get_imgheader(i, &header);
        len = sprintf(cmd, "%s image information:\r\n", 
            (i == 0) ? "First" : "Second");
        write(fd, cmd, len);
        memset(cmd, 0, sizeof(cmd));
        if (!ret) {
            len = sprintf(cmd, "   Image version: %s\r\n", &(header.ih_name[11]));
            write(fd, cmd, len);
            memset(cmd, 0, sizeof(cmd));
            timestamp = (time_t)ntohl(header.ih_time);
            ctime_r(&timestamp, time_str);
            len = sprintf(cmd, "   Created:       %s", time_str);
            write(fd, cmd, len);
            memset(cmd, 0, sizeof(cmd));
            len = sprintf(cmd, "   Data Size:     %d Bytes \r\n", ntohl(header.ih_size));
            write(fd, cmd, len);
            memset(cmd, 0, sizeof(cmd));
        }
        else {
            len = sprintf(cmd, "   Invalid image\r\n");
            write(fd, cmd, len);
            memset(cmd, 0, sizeof(cmd));
        }
    }

    return 0;
}

int show_led_status_info(int fd){
     led_status_s status[] = 
    {
//        {LED_ID_POWER,  LED_STATE_INVALID}, /* don't show power led */
        {LED_ID_STATUS, LED_STATE_INVALID},
        {LED_ID_LAN,    LED_STATE_INVALID},
        {LED_ID_WLAN0,  LED_STATE_INVALID},
        {LED_ID_WLAN1,  LED_STATE_INVALID}
    };
    int wlan_state = 0, i, k, size = sizeof(status)/sizeof(status[0]);
    struct product_info info;
    int len = 0;
    int mode = 0;
    char cmd[128] = {};

    cfg_get_product_info(&info);   
    if(!strncasecmp(info.production, "ap10", 4) || !strncasecmp(info.production, "ap20", 4)){
        mode = 0;
    }else{
        mode = 1;
    }

    len = sprintf(cmd, "LED status:\r\n");
    write(fd, cmd, len);
    memset(cmd, 0, sizeof(cmd));
    cfg_get_led_status(status, size);
    for (i = 0; i < size; i++) {
        if (status[i].state == LED_STATE_INVALID) {
            continue;
        }
        switch (status[i].id) {
            case LED_ID_POWER:
                len = sprintf(cmd, "   Power  LED: %s\r\n",
                    status[i].state == LED_STATE_ON ? "on" : "off");
                write(fd, cmd, len);
                memset(cmd, 0, sizeof(cmd));
                break;

            case LED_ID_STATUS:
                if(1 == mode){
                    len = sprintf(cmd, "   Status LED: ");
                    write(fd, cmd, len);
                    memset(cmd, 0, sizeof(cmd));
                    if (status[i].state <= LED_STATE_ON) {
                        len = sprintf(cmd, "%s\r\n", 
                            status[i].state == LED_STATE_ON ? "on" : "off");
                        write(fd, cmd, len);
                        memset(cmd, 0, sizeof(cmd));
                    }
                    else {
                        len = sprintf(cmd, "blink %s\r\n", 
                            status[i].state == LED_STATE_BLINK_FAST ? "fast" : "slowly");
                        write(fd, cmd, len);
                        memset(cmd, 0, sizeof(cmd));
                    }
                }
                break;

            case LED_ID_LAN:
                if(1 == mode){
                    len = sprintf(cmd, "   LAN    LED: %s\r\n",
                        status[i].state == LED_STATE_ON ? "on" : "off");
                    write(fd, cmd, len);
                    memset(cmd, 0, sizeof(cmd));
                }else{
                    len = sprintf(cmd, "   WAN    LED: %s\r\n",
                        status[i].state == LED_STATE_ON ? "on" : "off");
                    write(fd, cmd, len);
                    memset(cmd, 0, sizeof(cmd));
                }
                break;

            case LED_ID_WLAN0:
            case LED_ID_WLAN1:
                if (wlan_state) {
                    break;
                }
                for (k = 0; k < size; k++) {
                    if (status[k].id == LED_ID_WLAN0 ||
                        status[k].id == LED_ID_WLAN1) {
                        if (wlan_state > 0) {
                            status[k].state = LED_STATE_INVALID;
                        }
                        else {
                            wlan_state = (status[k].state == LED_STATE_ON);
                        }
                    }
                }
                len = sprintf(cmd, "   WLAN   LED: %s\r\n",
                    wlan_state > 0 ? "on" : "off");
                write(fd, cmd, len);
                memset(cmd, 0, sizeof(cmd));
                wlan_state ++;
                break;

            default:
                break;
        }
    }

    return 0;
}
#endif
void create_tech_support_file_cfg(char *IN_szFilePath) {
    
    char cmdline[128] = {0};

    sprintf(cmdline, "cp /proc/meminfo %s 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "cp /proc/slabinfo %s 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "dmesg > %s/dmesg 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "ps > %s/ps 2>&1", IN_szFilePath);
    system(cmdline);
    
    sprintf(cmdline, "ip route show > %s/iproute 2>&1", IN_szFilePath);
    system(cmdline);

    sprintf(cmdline, "cp /etc/config %s -fr", IN_szFilePath);
    system(cmdline);

    sprintf(cmdline, "cp /proc/net/arp %s ", IN_szFilePath);
    system(cmdline);

    sprintf(cmdline, "logread > %s/syslog 2>&1", IN_szFilePath);
    system(cmdline);

    /* added more info */
    sprintf(cmdline, "cat /proc/commsky/ResetReason > %s/ResetReason 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "cat /proc/commsky/panicinfo > %s/panicinfo 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "top -n 1 > %s/top 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "cat /proc/interrupts > %s/interrupts 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "date > %s/date 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "uptime > %s/uptime 2>&1", IN_szFilePath);
    system(cmdline);
    sprintf(cmdline, "cp /etc/flash_cfg/panic.tar.gz %s 2>/dev/null", IN_szFilePath);
    system(cmdline);

    sprintf(cmdline, "cat /proc/sys/net/netfilter/nf_conntrack_count > %s/nf_conntrack_count 2>/dev/null", IN_szFilePath);
    system(cmdline);

    system("cst_cli -s");

    #if 0
	create_device_file();
	create_version_file();
	create_dual_image_file();

    create_capwap_file();
    create_dhcp_file();
    create_interface_file();
    create_led_stats_file();
    create_mac_address_file();
    create_ntp_status_file();
    create_telnet_session_file();
    create_vlan_all_file();
    create_portal_file();
    create_running_config_file();
    
    create_debug_file();
    #endif

}

//end by puyg

/* added by lsz for oem package management */
int get_oem_default_hostname( char *value, unsigned char *mac ){
	struct json_object *rootObj, *obj, *tmp;
	int fix = 0;
	const char *prefix;

	rootObj = json_object_from_file( "/var/pkg_web/oem_info");
	if ( is_error(rootObj) ) {
		DEBUG( "Cannot find root object. Reason:%ld\n", (long)0 - (long)rootObj );
		return -1;
	} else {
		obj = json_object_object_get( rootObj, "hostname" );
		if ( obj != NULL && json_object_get_type(obj) == json_type_object ) {
			tmp = json_object_object_get( obj, "fix" );
			if ( tmp != NULL && json_object_get_type(tmp) == json_type_int ) {
				fix = json_object_get_int( tmp );
			}

			tmp = json_object_object_get( obj, "prefix" );
			if ( tmp != NULL && json_object_get_type(tmp) == json_type_string ) {
				prefix = json_object_get_string( tmp );
			}

			if ( fix == 1) {
				sprintf(value, "%s", prefix);
			} else {
				sprintf(value, "%s%c%c%c%c%c%c", 
						prefix,
						toupper(mac[9]), toupper(mac[10]),
						toupper(mac[12]), toupper(mac[13]),
						toupper(mac[15]), toupper(mac[16])
				);
			}
		} else {
			json_object_put( rootObj );
			return -1;
		}
	}

	json_object_put( rootObj );
	return 0;
}
/* added by lsz for oem package management, end */

int cfg_get_default_hostname(char * value)
{
    struct product_info info;
    int ret;
    unsigned char * mac = NULL;

    ret = cfg_get_product_info(&info);
    if (ret) {
        return ret;
    }

    if (info.mac[0] == 0) {
        return -1;  // no MAC info
    }
    mac = (unsigned char * )info.mac;

	/* added by lsz for oem package management */
	if ( get_oem_default_hostname(value, mac) != 0 ) {
		sprintf(value, "CST-AP%c%c%c%c%c%c", 
				toupper(mac[9]), toupper(mac[10]),
				toupper(mac[12]), toupper(mac[13]),
				toupper(mac[15]), toupper(mac[16])
		);
	}
	/* added by lsz for oem package management, end */


#if 0
#ifdef HOSTNAME_PREFIX
#define _STR(x) #x
#define STR(x)  _STR(x)
    sprintf(value, "%s-AP%c%c%c%c%c%c", 
			STR(HOSTNAME_PREFIX),
            toupper(mac[9]), toupper(mac[10]),
            toupper(mac[12]), toupper(mac[13]),
            toupper(mac[15]), toupper(mac[16]));
#else
    sprintf(value, "CST-AP%c%c%c%c%c%c", 
            toupper(mac[9]), toupper(mac[10]),
            toupper(mac[12]), toupper(mac[13]),
            toupper(mac[15]), toupper(mac[16]));
#endif
#endif

    return 0;
}

int cfg_has_feature(const char * feature)
{
    char    filename[128];

    sprintf(filename, "/etc/custom/feature_%s", feature);

    return access(filename, R_OK) == 0;
}

int cfg_product_has_smartantenna(void)
{
    return cfg_has_feature("smartenna");
}

#include <syslog.h>

int cfg_get_device_mode(void)
{
    FILE * fp;
    char    mode[128];

    fp = fopen("/etc/device_mode", "r");
    if (fp  == NULL) {
        printf("FATAL ERROR: preinit does not export DEVICE_MODE!\n");
        syslog(LOG_ERR, "FATAL ERROR: preinit does not export DEVICE_MODE!\n");
        exit(-1);
    }

    fgets(mode, sizeof(mode) - 1, fp);
    mode[sizeof(mode) - 1] = 0;
    fclose(fp);

    if (strcasecmp(mode, "fat") == 0) {
        return DEVICE_MODE_FAT;
    }
    else if (strcasecmp(mode, "fit") == 0) {
        return DEVICE_MODE_FIT;
    }

    printf("FATAL ERROR: Corrupt DEVICE_MODE enviroment!\n");
    syslog(LOG_ERR, "FATAL ERROR: Corrupt DEVICE_MODE enviroment!\n");

    return DEVICE_MODE_FAT;
}

int cfg_set_device_mode(int mode)
{
    if (mode == DEVICE_MODE_FAT) {
        return system("fw_setenv -s device_mode fat");
    }
    else {
        return system("fw_setenv -s device_mode fit");
    }

    return 0;
}

