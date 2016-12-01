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

#ifndef __CFG_INTERNAL_H
#define __CFG_INTERNAL_H

#include <stdbool.h>

#define __private __attribute__((visibility("hidden")))
#define __public

struct cfg_parse_context
{
	/* error context */
	const char *reason;
	int line;
	int byte;

	/* private: */
	struct cfg_package *package;
	struct cfg_section *section;
	bool merge;
	FILE *file;
	const char *name;
	char *buf;
	int bufsz;
};

extern const char *cfg_confdir;
extern const char *cfg_savedir;

__private void *cfg_malloc(struct cfg_context *ctx, size_t size);
__private void *cfg_realloc(struct cfg_context *ctx, void *ptr, size_t size);
__private char *cfg_strdup(struct cfg_context *ctx, const char *str);
__private bool cfg_validate_str(const char *str, bool name);
__private void cfg_add_delta(struct cfg_context *ctx, struct cfg_list *list, int cmd, const char *section, const char *option, const char *value);
__private void cfg_free_delta(struct cfg_delta *h);
__private struct cfg_package *cfg_alloc_package(struct cfg_context *ctx, const char *name);

__private FILE *cfg_open_stream(struct cfg_context *ctx, const char *filename, const char *origfilename, int pos, bool write, bool create);
__private void cfg_close_stream(FILE *stream);
__private void cfg_getln(struct cfg_context *ctx, int offset);

__private void cfg_parse_error(struct cfg_context *ctx, char *pos, char *reason);
__private void cfg_alloc_parse_context(struct cfg_context *ctx);

__private void cfg_cleanup(struct cfg_context *ctx);
__private struct cfg_element *cfg_lookup_list(struct cfg_list *list, const char *name);
__private void cfg_fixup_section(struct cfg_context *ctx, struct cfg_section *s);
__private void cfg_free_package(struct cfg_package **package);
__private struct cfg_element *cfg_alloc_generic(struct cfg_context *ctx, int type, const char *name, int size);
__private void cfg_free_element(struct cfg_element *e);
__private struct cfg_element *cfg_expand_ptr(struct cfg_context *ctx, struct cfg_ptr *ptr, bool complete);

__private int cfg_load_delta(struct cfg_context *ctx, struct cfg_package *p, bool flush);

static inline bool cfg_validate_package(const char *str)
{
	return cfg_validate_str(str, false);
}

static inline bool cfg_validate_type(const char *str)
{
	return cfg_validate_str(str, false);
}

static inline bool cfg_validate_name(const char *str)
{
	return cfg_validate_str(str, true);
}

/* initialize a list head/item */
static inline void cfg_list_init(struct cfg_list *ptr)
{
	ptr->prev = ptr;
	ptr->next = ptr;
}

/* inserts a new list entry after a given entry */
static inline void cfg_list_insert(struct cfg_list *list, struct cfg_list *ptr)
{
	list->next->prev = ptr;
	ptr->prev = list;
	ptr->next = list->next;
	list->next = ptr;
}

/* inserts a new list entry at the tail of the list */
static inline void cfg_list_add(struct cfg_list *head, struct cfg_list *ptr)
{
	/* NB: head->prev points at the tail */
	cfg_list_insert(head->prev, ptr);
}

static inline void cfg_list_del(struct cfg_list *ptr)
{
	struct cfg_list *next, *prev;

	next = ptr->next;
	prev = ptr->prev;

	prev->next = next;
	next->prev = prev;

	cfg_list_init(ptr);
}


extern struct cfg_backend cfg_file_backend;

#ifdef CFG_PLUGIN_SUPPORT
/**
 * cfg_add_backend: add an extra backend
 * @ctx: cfg context
 * @name: name of the backend
 *
 * The default backend is "file", which uses /etc/config for config storage
 */
__private int cfg_add_backend(struct cfg_context *ctx, struct cfg_backend *b);

/**
 * cfg_add_backend: add an extra backend
 * @ctx: cfg context
 * @name: name of the backend
 *
 * The default backend is "file", which uses /etc/config for config storage
 */
__private int cfg_del_backend(struct cfg_context *ctx, struct cfg_backend *b);
#endif

#define CFG_BACKEND(_var, _name, ...)	\
struct cfg_backend _var = {		\
	.e.list = {			\
		.next = &_var.e.list,	\
		.prev = &_var.e.list,	\
	},				\
	.e.name = _name,		\
	.e.type = CFG_TYPE_BACKEND,	\
	.ptr = &_var,			\
	__VA_ARGS__			\
}


/*
 * functions for debug and error handling, for internal use only
 */

#ifdef CFG_DEBUG
#define DPRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
#define DPRINTF(...)
#endif

/*
 * throw an cfg exception and store the error number
 * in the context.
 */
#define CFG_THROW(ctx, err) do { 	\
	DPRINTF("Exception: %s in %s, %s:%d\n", #err, __func__, __FILE__, __LINE__); \
	longjmp(ctx->trap, err); 	\
} while (0)

/*
 * store the return address for handling exceptions
 * needs to be called in every externally visible library function
 *
 * NB: this does not handle recursion at all. Calling externally visible
 * functions from other cfg functions is only allowed at the end of the
 * calling function, or by wrapping the function call in CFG_TRAP_SAVE
 * and CFG_TRAP_RESTORE.
 */
#define CFG_HANDLE_ERR(ctx) do {	\
	DPRINTF("ENTER: %s\n", __func__); \
	int __val = 0;			\
	if (!ctx)			\
		return CFG_ERR_INVAL;	\
	ctx->err = 0;			\
	if (!ctx->internal && !ctx->nested) \
		__val = setjmp(ctx->trap); \
	ctx->internal = false;		\
	ctx->nested = false;		\
	if (__val) {			\
		DPRINTF("LEAVE: %s, ret=%d\n", __func__, __val); \
		ctx->err = __val;	\
		return __val;		\
	}				\
} while (0)

/*
 * In a block enclosed by CFG_TRAP_SAVE and CFG_TRAP_RESTORE, all exceptions
 * are intercepted and redirected to the label specified in 'handler'
 * after CFG_TRAP_RESTORE, or when reaching the 'handler' label, the old
 * exception handler is restored
 */
#define CFG_TRAP_SAVE(ctx, handler) do {   \
	jmp_buf	__old_trap;		\
	int __val;			\
	memcpy(__old_trap, ctx->trap, sizeof(ctx->trap)); \
	__val = setjmp(ctx->trap);	\
	if (__val) {			\
		ctx->err = __val;	\
		memcpy(ctx->trap, __old_trap, sizeof(ctx->trap)); \
		goto handler;		\
	}
#define CFG_TRAP_RESTORE(ctx)		\
	memcpy(ctx->trap, __old_trap, sizeof(ctx->trap)); \
} while(0)

/**
 * CFG_INTERNAL: Do an internal call of a public API function
 *
 * Sets Exception handling to passthrough mode.
 * Allows API functions to change behavior compared to public use
 */
#define CFG_INTERNAL(func, ctx, ...) do { \
	ctx->internal = true;		\
	func(ctx, __VA_ARGS__);		\
} while (0)

/**
 * CFG_NESTED: Do an normal nested call of a public API function
 *
 * Sets Exception handling to passthrough mode.
 * Allows API functions to change behavior compared to public use
 */
#define CFG_NESTED(func, ctx, ...) do { \
	ctx->nested = true;		\
	func(ctx, __VA_ARGS__);		\
} while (0)


/*
 * check the specified condition.
 * throw an invalid argument exception if it's false
 */
#define CFG_ASSERT(ctx, expr) do {	\
	if (!(expr)) {			\
		DPRINTF("[%s:%d] Assertion failed\n", __FILE__, __LINE__); \
		CFG_THROW(ctx, CFG_ERR_INVAL);	\
	}				\
} while (0)

#endif
