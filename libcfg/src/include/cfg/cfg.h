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

#ifndef __LIBCFG_H
#define __LIBCFG_H

#ifdef __cplusplus
extern "C" {
#endif

//#include "cfg_config.h"

/*
 * you can use these defines to enable debugging behavior for
 * apps compiled against libcfg:
 *
 * #define CFG_DEBUG_TYPECAST:
 *   enable cfg_element typecast checking at run time
 *
 */

#include <stdbool.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CFG_CONFDIR   "/etc/config"
#define CFG_SAVEDIR   "/tmp/.cfg"
#define CFG_DIRMODE   0700
#define CFG_FILEMODE  0600

#define CFG_LOAD_DIR  "/tmp"
#define CFG_LOAD_FILE "running.cfg"

enum
{
	CFG_OK = 0,
	CFG_ERR_MEM,
	CFG_ERR_INVAL,
	CFG_ERR_NOTFOUND,
	CFG_ERR_IO,
	CFG_ERR_PARSE,
	CFG_ERR_DUPLICATE,
	CFG_ERR_UNKNOWN,
	CFG_ERR_LAST
};

struct cfg_list;
struct cfg_list
{
	struct cfg_list *next;
	struct cfg_list *prev;
};

struct cfg_ptr;
struct cfg_element;
struct cfg_package;
struct cfg_section;
struct cfg_option;
struct cfg_delta;
struct cfg_context;
struct cfg_backend;
struct cfg_parse_option;
struct cfg_parse_context;


/**
 * cfg_alloc_context: Allocate a new cfg context
 */
extern struct cfg_context *cfg_alloc_context(void);

/**
 * cfg_free_context: Free the cfg context including all of its data
 */
extern void cfg_free_context(struct cfg_context *ctx);

/**
 * cfg_perror: Print the last cfg error that occured
 * @ctx: cfg context
 * @str: string to print before the error message
 */
extern void cfg_perror(struct cfg_context *ctx, const char *str);

/**
 * cfg_geterror: Get an error string for the last cfg error
 * @ctx: cfg context
 * @dest: target pointer for the string
 * @str: prefix for the error message
 *
 * Note: string must be freed by the caller
 */
extern void cfg_get_errorstr(struct cfg_context *ctx, char **dest, const char *str);

/**
 * cfg_import: Import cfg config data from a stream
 * @ctx: cfg context
 * @stream: file stream to import from
 * @name: (optional) assume the config has the given name
 * @package: (optional) store the last parsed config package in this variable
 * @single: ignore the 'package' keyword and parse everything into a single package
 *
 * the name parameter is for config files that don't explicitly use the 'package <...>' keyword
 * if 'package' points to a non-null struct pointer, enable delta tracking and merge
 */
extern int cfg_import(struct cfg_context *ctx, FILE *stream, const char *name, struct cfg_package **package, bool single);

/**
 * cfg_export: Export one or all cfg config packages
 * @ctx: cfg context
 * @stream: output stream
 * @package: (optional) cfg config package to export
 * @header: include the package header
 */
extern int cfg_export(struct cfg_context *ctx, FILE *stream, struct cfg_package *package, bool header);

/**
 * cfg_load: Parse an cfg config file and store it in the cfg context
 *
 * @ctx: cfg context
 * @name: name of the config file (relative to the config directory)
 * @package: store the loaded config package in this variable
 */
extern int cfg_load(struct cfg_context *ctx, const char *name, struct cfg_package **package);

/**
 * cfg_unload: Unload a config file from the cfg context
 *
 * @ctx: cfg context
 * @package: pointer to the cfg_package struct
 */
extern int cfg_unload(struct cfg_context *ctx, struct cfg_package *p);

/**
 * cfg_lookup_ptr: Split an cfg tuple string and look up an element tree
 * @ctx: cfg context
 * @ptr: lookup result struct
 * @str: cfg tuple string to look up
 * @extended: allow extended syntax lookup
 *
 * if extended is set to true, cfg_lookup_ptr supports the following
 * extended syntax:
 *
 * Examples:
 *   network.@interface[0].ifname ('ifname' option of the first interface section)
 *   network.@interface[-1]       (last interface section)
 * Note: cfg_lookup_ptr will automatically load a config package if necessary
 * @str must not be constant, as it will be modified and used for the strings inside @ptr,
 * thus it must also be available as long as @ptr is in use.
 */
extern int cfg_lookup_ptr(struct cfg_context *ctx, struct cfg_ptr *ptr, char *str, bool extended);

/**
 * cfg_add_section: Add an unnamed section
 * @ctx: cfg context
 * @p: package to add the section to
 * @type: section type
 * @res: pointer to store a reference to the new section in
 */
extern int cfg_add_section(struct cfg_context *ctx, struct cfg_package *p, const char *type, struct cfg_section **res);

/**
 * cfg_set: Set an element's value; create the element if necessary
 * @ctx: cfg context
 * @ptr: cfg pointer
 *
 * The updated/created element is stored in ptr->last
 */
extern int cfg_set(struct cfg_context *ctx, struct cfg_ptr *ptr);

/**
 * cfg_add_list: Append a string to an element list
 * @ctx: cfg context
 * @ptr: cfg pointer (with value)
 *
 * Note: if the given option already contains a string value,
 * it will be converted to an 1-element-list before appending the next element
 */
extern int cfg_add_list(struct cfg_context *ctx, struct cfg_ptr *ptr);

/**
 * cfg_del_list: Remove a string from an element list
 * @ctx: cfg context
 * @ptr: cfg pointer (with value)
 *
 */
extern int cfg_del_list(struct cfg_context *ctx, struct cfg_ptr *ptr);

/**
 * cfg_reorder: Reposition a section
 * @ctx: cfg context
 * @s: cfg section to reposition
 * @pos: new position in the section list
 */
extern int cfg_reorder_section(struct cfg_context *ctx, struct cfg_section *s, int pos);

/**
 * cfg_rename: Rename an element
 * @ctx: cfg context
 * @ptr: cfg pointer (with value)
 */
extern int cfg_rename(struct cfg_context *ctx, struct cfg_ptr *ptr);

/**
 * cfg_delete: Delete a section or option
 * @ctx: cfg context
 * @ptr: cfg pointer
 */
extern int cfg_delete(struct cfg_context *ctx, struct cfg_ptr *ptr);

/**
 * cfg_save: save change delta for a package
 * @ctx: cfg context
 * @p: cfg_package struct
 */
extern int cfg_save(struct cfg_context *ctx, struct cfg_package *p);

/**
 * cfg_commit: commit changes to a package
 * @ctx: cfg context
 * @p: cfg_package struct pointer
 * @overwrite: overwrite existing config data and flush delta
 *
 * committing may reload the whole cfg_package data,
 * the supplied pointer is updated accordingly
 */
extern int cfg_commit(struct cfg_context *ctx, struct cfg_package **p, bool overwrite);

/**
 * cfg_list_configs: List available cfg config files
 * @ctx: cfg context
 *
 * caller is responsible for freeing the allocated memory behind list
 */
extern int cfg_list_configs(struct cfg_context *ctx, char ***list);

/**
 * cfg_set_savedir: override the default delta save directory
 * @ctx: cfg context
 * @dir: directory name
 */
extern int cfg_set_savedir(struct cfg_context *ctx, const char *dir);

/**
 * cfg_set_savedir: override the default config storage directory
 * @ctx: cfg context
 * @dir: directory name
 */
extern int cfg_set_confdir(struct cfg_context *ctx, const char *dir);

/**
 * cfg_add_delta_path: add a directory to the search path for change delta files
 * @ctx: cfg context
 * @dir: directory name
 *
 * This function allows you to add directories, which contain 'overlays'
 * for the active config, that will never be committed.
 */
extern int cfg_add_delta_path(struct cfg_context *ctx, const char *dir);

/**
 * cfg_revert: revert all changes to a config item
 * @ctx: cfg context
 * @ptr: cfg pointer
 */
extern int cfg_revert(struct cfg_context *ctx, struct cfg_ptr *ptr);

/**
 * cfg_parse_argument: parse a shell-style argument, with an arbitrary quoting style
 * @ctx: cfg context
 * @stream: input stream
 * @str: pointer to the current line (use NULL for parsing the next line)
 * @result: pointer for the result
 */
extern int cfg_parse_argument(struct cfg_context *ctx, FILE *stream, char **str, char **result);

/**
 * cfg_set_backend: change the default backend
 * @ctx: cfg context
 * @name: name of the backend
 *
 * The default backend is "file", which uses /etc/config for config storage
 */
extern int cfg_set_backend(struct cfg_context *ctx, const char *name);

/**
 * cfg_validate_text: validate a value string for cfg options
 * @str: value
 *
 * this function checks whether a given string is acceptable as value
 * for cfg options
 */
extern bool cfg_validate_text(const char *str);

/**
 * cfg_parse_ptr: parse a cfg string into a cfg_ptr
 * @ctx: cfg context
 * @ptr: target data structure
 * @str: string to parse
 *
 * str is modified by this function
 */
int cfg_parse_ptr(struct cfg_context *ctx, struct cfg_ptr *ptr, char *str);

/**
 * cfg_lookup_next: lookup a child element
 * @ctx: cfg context
 * @e: target element pointer
 * @list: list of elements
 * @name: name of the child element
 *
 * if parent is NULL, the function looks up the package with the given name
 */
int cfg_lookup_next(struct cfg_context *ctx, struct cfg_element **e, struct cfg_list *list, const char *name);

/**
 * cfg_parse_section: look up a set of options
 * @s: cfg section
 * @opts: list of options to look up
 * @n_opts: number of options to look up
 * @tb: array of pointers to found options
 */
void cfg_parse_section(struct cfg_section *s, const struct cfg_parse_option *opts,
		       int n_opts, struct cfg_option **tb);

/**
 * cfg_hash_options: build a hash over a list of options
 * @tb: list of option pointers
 * @n_opts: number of options
 */
uint32_t cfg_hash_options(struct cfg_option **tb, int n_opts);


/* CFG data structures */
enum cfg_type {
	CFG_TYPE_UNSPEC = 0,
	CFG_TYPE_DELTA = 1,
	CFG_TYPE_PACKAGE = 2,
	CFG_TYPE_SECTION = 3,
	CFG_TYPE_OPTION = 4,
	CFG_TYPE_PATH = 5,
	CFG_TYPE_BACKEND = 6,
	CFG_TYPE_ITEM = 7,
	CFG_TYPE_HOOK = 8,
};

enum cfg_option_type {
	CFG_TYPE_STRING = 0,
	CFG_TYPE_LIST = 1,
};

enum cfg_flags {
	CFG_FLAG_STRICT =        (1 << 0), /* strict mode for the parser */
	CFG_FLAG_PERROR =        (1 << 1), /* print parser error messages */
	CFG_FLAG_EXPORT_NAME =   (1 << 2), /* when exporting, name unnamed sections */
	CFG_FLAG_SAVED_DELTA = (1 << 3), /* store the saved delta in memory as well */
};

struct cfg_element
{
	struct cfg_list list;
	enum cfg_type type;
	char *name;
};

struct cfg_backend
{
	struct cfg_element e;
	char **(*list_configs)(struct cfg_context *ctx);
	struct cfg_package *(*load)(struct cfg_context *ctx, const char *name);
	void (*commit)(struct cfg_context *ctx, struct cfg_package **p, bool overwrite);

	/* private: */
	const void *ptr;
	void *priv;
};

struct cfg_context
{
	/* list of config packages */
	struct cfg_list root;

	/* parser context, use for error handling only */
	struct cfg_parse_context *pctx;

	/* backend for import and export */
	struct cfg_backend *backend;
	struct cfg_list backends;

	/* cfg runtime flags */
	enum cfg_flags flags;

	char *confdir;
	char *savedir;

	/* search path for delta files */
	struct cfg_list delta_path;

	/* private: */
	int err;
	const char *func;
	jmp_buf trap;
	bool internal, nested;
	char *buf;
	int bufsz;
};

struct cfg_package
{
	struct cfg_element e;
	struct cfg_list sections;
	struct cfg_context *ctx;
	bool has_delta;
	char *path;

	/* private: */
	struct cfg_backend *backend;
	void *priv;
	int n_section;
	struct cfg_list delta;
	struct cfg_list saved_delta;
};

struct cfg_section
{
	struct cfg_element e;
	struct cfg_list options;
	struct cfg_package *package;
	bool anonymous;
	char *type;
};

struct cfg_option
{
	struct cfg_element e;
	struct cfg_section *section;
	enum cfg_option_type type;
	union {
		struct cfg_list list;
		char *string;
	} v;
};

enum cfg_command {
	CFG_CMD_ADD,
	CFG_CMD_REMOVE,
	CFG_CMD_CHANGE,
	CFG_CMD_RENAME,
	CFG_CMD_REORDER,
	CFG_CMD_LIST_ADD,
	CFG_CMD_LIST_DEL,
};

struct cfg_delta
{
	struct cfg_element e;
	enum cfg_command cmd;
	char *section;
	char *value;
};

struct cfg_ptr
{
	enum cfg_type target;
	enum {
		CFG_LOOKUP_DONE =     (1 << 0),
		CFG_LOOKUP_COMPLETE = (1 << 1),
		CFG_LOOKUP_EXTENDED = (1 << 2),
	} flags;

	struct cfg_package *p;
	struct cfg_section *s;
	struct cfg_option *o;
	struct cfg_element *last;

	const char *package;
	const char *section;
	const char *option;
	const char *value;
};

struct cfg_parse_option {
	const char *name;
	enum cfg_option_type type;
};


/* linked list handling */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#ifndef container_of
#define container_of(ptr, type, member) \
	((type *) ((char *)ptr - offsetof(type,member)))
#endif


/**
 * cfg_list_entry: casts an cfg_list pointer to the containing struct.
 * @_type: config, section or option
 * @_ptr: pointer to the cfg_list struct
 */
#define list_to_element(ptr) \
	container_of(ptr, struct cfg_element, list)

/**
 * cfg_foreach_entry: loop through a list of cfg elements
 * @_list: pointer to the cfg_list struct
 * @_ptr: iteration variable, struct cfg_element
 *
 * use like a for loop, e.g:
 *   cfg_foreach(&list, p) {
 *   	...
 *   }
 */
#define cfg_foreach_element(_list, _ptr)		\
	for(_ptr = list_to_element((_list)->next);	\
		&_ptr->list != (_list);			\
		_ptr = list_to_element(_ptr->list.next))

/**
 * cfg_foreach_entry_safe: like cfg_foreach_safe, but safe for deletion
 * @_list: pointer to the cfg_list struct
 * @_tmp: temporary variable, struct cfg_element *
 * @_ptr: iteration variable, struct cfg_element *
 *
 * use like a for loop, e.g:
 *   cfg_foreach(&list, p) {
 *   	...
 *   }
 */
#define cfg_foreach_element_safe(_list, _tmp, _ptr)		\
	for(_ptr = list_to_element((_list)->next),		\
		_tmp = list_to_element(_ptr->list.next);	\
		&_ptr->list != (_list);			\
		_ptr = _tmp, _tmp = list_to_element(_ptr->list.next))

/**
 * cfg_list_empty: returns true if a list is empty
 * @list: list head
 */
#define cfg_list_empty(list) ((list)->next == (list))

/* wrappers for dynamic type handling */
#define cfg_type_backend CFG_TYPE_BACKEND
#define cfg_type_delta CFG_TYPE_DELTA
#define cfg_type_package CFG_TYPE_PACKAGE
#define cfg_type_section CFG_TYPE_SECTION
#define cfg_type_option CFG_TYPE_OPTION

/* element typecasting */
#ifdef CFG_DEBUG_TYPECAST
static const char *cfg_typestr[] = {
	[cfg_type_backend] = "backend",
	[cfg_type_delta] = "delta",
	[cfg_type_package] = "package",
	[cfg_type_section] = "section",
	[cfg_type_option] = "option",
};

static void cfg_typecast_error(int from, int to)
{
	fprintf(stderr, "Invalid typecast from '%s' to '%s'\n", cfg_typestr[from], cfg_typestr[to]);
}

#define BUILD_CAST(_type) \
	static inline struct cfg_ ## _type *cfg_to_ ## _type (struct cfg_element *e) \
	{ \
		if (e->type != cfg_type_ ## _type) { \
			cfg_typecast_error(e->type, cfg_type_ ## _type); \
		} \
		return (struct cfg_ ## _type *) e; \
	}

BUILD_CAST(backend)
BUILD_CAST(delta)
BUILD_CAST(package)
BUILD_CAST(section)
BUILD_CAST(option)

#else
#define cfg_to_backend(ptr) container_of(ptr, struct cfg_backend, e)
#define cfg_to_delta(ptr) container_of(ptr, struct cfg_delta, e)
#define cfg_to_package(ptr) container_of(ptr, struct cfg_package, e)
#define cfg_to_section(ptr) container_of(ptr, struct cfg_section, e)
#define cfg_to_option(ptr)  container_of(ptr, struct cfg_option, e)
#endif

/**
 * cfg_alloc_element: allocate a generic cfg_element, reserve a buffer and typecast
 * @ctx: cfg context
 * @type: {package,section,option}
 * @name: string containing the name of the element
 * @datasize: additional buffer size to reserve at the end of the struct
 */
#define cfg_alloc_element(ctx, type, name, datasize) \
	cfg_to_ ## type (cfg_alloc_generic(ctx, cfg_type_ ## type, name, sizeof(struct cfg_ ## type) + datasize))

#define cfg_dataptr(ptr) \
	(((char *) ptr) + sizeof(*ptr))

/**
 * cfg_lookup_package: look up a package
 * @ctx: cfg context
 * @name: name of the package
 */
static inline struct cfg_package *
cfg_lookup_package(struct cfg_context *ctx, const char *name)
{
	struct cfg_element *e = NULL;
	if (cfg_lookup_next(ctx, &e, &ctx->root, name) == 0)
		return cfg_to_package(e);
	else
		return NULL;
}

/**
 * cfg_lookup_section: look up a section
 * @ctx: cfg context
 * @p: package that the section belongs to
 * @name: name of the section
 */
static inline struct cfg_section *
cfg_lookup_section(struct cfg_context *ctx, struct cfg_package *p, const char *name)
{
	struct cfg_element *e = NULL;
	if (cfg_lookup_next(ctx, &e, &p->sections, name) == 0)
		return cfg_to_section(e);
	else
		return NULL;
}

/**
 * cfg_lookup_option: look up an option
 * @ctx: cfg context
 * @section: section that the option belongs to
 * @name: name of the option
 */
static inline struct cfg_option *
cfg_lookup_option(struct cfg_context *ctx, struct cfg_section *s, const char *name)
{
	struct cfg_element *e = NULL;
	if (cfg_lookup_next(ctx, &e, &s->options, name) == 0)
		return cfg_to_option(e);
	else
		return NULL;
}

static inline const char *
cfg_lookup_option_string(struct cfg_context *ctx, struct cfg_section *s, const char *name)
{
	struct cfg_option *o;

	o = cfg_lookup_option(ctx, s, name);
	if (!o || o->type != CFG_TYPE_STRING)
		return NULL;

	return o->v.string;
}

/*
 *
 * RETURN VALUE:
 * < 0 : error
 * otherwise : return the value given by @visitor
 */
extern int cfg_visit_package(const char * tuple,
        int (*visitor)(struct cfg_package *, void *),
        void * arg);

/*
 * @start_row: return value will control what to happen:
 * < 0 : error, return immediatly
 * >= 0: keep going
 *
 * @visitor: return value will control what to happen:
 * < 0 : error, return immediatly
 * = 0 : no error, but stop going, call @end_row if valid, and return 0 
 * > 0 : no error and is user definied, keep going
 *
 * RETURN VALUE:
 * < 0 : error
 * = 0 : OK but user stop walking or NO ANY ROW EXISTS
 * > 0 : OK and is the last value return by @visitor
 */

#if 0
#define CFG_START_ERROR -1
#define CFG_START_SKIP  0
#define CFG_START_OK    1
#endif

#define CFG_VISIT_ERROR -1
#define CFG_VISIT_STOP  0
#define CFG_VISIT_OK    1

#define CFG_ENABLED_FIELD_VALUE     "enabled"
#define CFG_DISABLED_FIELD_VALUE    "disabled"

extern int cfg_visit_row(const char * tuple,
        int (*visitor)(int /* row */, struct cfg_section *, void *),
        void * arg);

int cfg_get_default_value(const char * table, const char * id, 
        const char * field, char * value, int length);
/* SELECT @field FROM @table WHERE id=@id */
extern int cfg_get_value(const char * table, const char * id, 
        const char * field, char * value, int length);

extern int cfg_get_int(const char * table, const char * id, 
        const char * field, int * value);

extern int cfg_get_enable(const char * table, const char * id, 
        const char * field, int * enable);

/* DELETE * FROM @table WHERE id=@id */
extern int cfg_del_row(const char * table, const char * id);
extern int cfg_add_row(const char * table, const char * id);

extern int cfg_set_value(const char * table, 
        const char * id, const char * field, const char * value);
static inline int cfg_set_int(const char * table, 
        const char * id, const char * field, int value)
{
    char    buf[32];
    sprintf(buf, "%d", value);
    return cfg_set_value(table, id, field, buf);
}
static inline int cfg_set_int_or_auto(const char * table, 
        const char * id, const char * field, int value)
{
    char    buf[32];
    if (value) {
        sprintf(buf, "%d", value);
    }
    else {
        strcpy(buf, "auto");
    }
    return cfg_set_value(table, id, field, buf);
}
static inline int cfg_set_enabled(const char * table, 
        const char * id, const char * field, int value)
{
    return cfg_set_value(table, id, field, value ? CFG_ENABLED_FIELD_VALUE : CFG_DISABLED_FIELD_VALUE);
}

#if 0
extern int cfg_set_value_lockless(const char * table, 
        const char * id, const char * field, const char * value);
#endif

extern int cfg_reset_module(const char * module);
extern int cfg_truncate_module(const char * module);
extern int cfg_del_item(const char * table, const char * id, const char * field);

extern int cfg_add_list_value(const char * table, 
        const char * id, const char * field, const char * value);
extern int cfg_del_list_value(const char * table, 
        const char * id, const char * field, const char * value);

extern int cfg_get_spec(const char * module);

extern int cfg_restore();
extern int cfg_save_all(int force);

extern int cfg_reset_factory(void);

extern int cfg_show_running_config(int fd);
extern int cfg_upload_config(void);
extern void cfg_upload_cleanup(void);
extern int cfg_download_config(void);
extern void cfg_dowanload_cleanup(void);

extern int cfg_get_env(const char * key, char * value, int size);
enum upgrade_failed_e{
    MTDDEV_GET_FAILED = -1,
    VERSION_MATCH_FAILED = -2,
    IMG_UPGRADE_FAILED = -3,
    BOOTIMG_SET_FAILED = -4
};
extern int cfg_upgrade_image(const char *imagefile);

//#define ETHER_MAC_ENV   "ethernet_mac"
//#define WLAN_MAC_ENV    "wlan_mac"
//#define VLAN_MAC_ENV    "vlan_mac"
#define MAC_ENV         "mac"
#define MODEL_ENV       "model"

struct product_info {
    char    company[12];    // short name
    char    production[20]; // formed at compiled time, used by inner program
    char    model[24];      // come from manufactory data, seen by custom
    char    mac[20];
    char    bootloader_version[24];
    char    software_version[24];
    char    software_inner_version[24];
    char    hardware_version[24];
    char    production_match[16];
    char    serial[36];
    unsigned long   software_buildtime;
    unsigned long   bootloader_buildtime;
};

#define IH_MAGIC	0x27051956	/* Image Magic Number		*/

/*
 * all data in network byte order (aka natural aka bigendian)
 */
typedef struct image_header {
	uint32_t	ih_magic;	/* Image Header Magic Number	*/
	uint32_t	ih_hcrc;	/* Image Header CRC Checksum	*/
	uint32_t	ih_time;	/* Image Creation Timestamp	*/
	uint32_t	ih_size;	/* Image Data Size		*/
	uint32_t	ih_load;	/* Data	 Load  Address		*/
	uint32_t	ih_ep;		/* Entry Point Address		*/
	uint32_t	ih_dcrc;	/* Image Data CRC Checksum	*/
	uint8_t		ih_os;		/* Operating System		*/
	uint8_t		ih_arch;	/* CPU architecture		*/
	uint8_t		ih_type;	/* Image Type			*/
	uint8_t		ih_comp;	/* Compression Type		*/
	uint8_t		ih_name[32];	/* Image Name		*/
} image_header_t;

typedef enum led_id {
    LED_ID_POWER = 0,
    LED_ID_STATUS,
    LED_ID_LAN,
    LED_ID_LAN1,
    LED_ID_LAN2,
    LED_ID_WAN,
    LED_ID_WLAN,
    LED_ID_WLAN0,
    LED_ID_WLAN1,
    LED_ID_RGB,
    LED_ID_INVALID
} led_id_e;

typedef enum led_state {
    LED_STATE_OFF = 1,
    LED_STATE_ON,
    LED_STATE_BLINK_SLOWLY,
    LED_STATE_BLINK_FAST,
    LED_STATE_INVALID
} led_state_e;

typedef enum led_product {
    LED_PANEL_AP_e = 0,
    LED_11n_AP35,
    LED_11n_AP36,
    LED_11ac_AP_IN,
    LED_11ac_AP_OUT,
    LED_WRT_AP,
    LED_AP_INVALID
} led_product_e;


typedef struct {
    led_id_e id;
    led_state_e state;
    char ident[16];
} led_status_s;

extern int cfg_get_led_status(led_status_s *status, int num, led_product_e product);


extern int cfg_get_product_info(struct product_info * info);
// return value: 0 for match
extern int cfg_compare_product_match(const char * str1, const char * str2);

extern int cfg_boot_from(void);
extern int cfg_get_imgheader(int imgnum, image_header_t *header);

//add by puyg
/*extern int show_device_info(int fd);
extern int show_version_info(int fd);
extern int show_dual_image_info(int fd);
extern int show_led_status_info(int fd);*/
extern void create_tech_support_file_cfg(char *IN_szFilePath);

//end by puyg


/***************for config version***********************/
extern void cfg_set_version(int version);
extern int cfg_get_version(void);
extern void cfg_disable_version_notice(void);
extern void cfg_enable_version_notice(void);
extern int cfg_update_notice(void);

extern int cfg_get_default_hostname(char * value);

extern int cfg_has_feature(const char * feature);
extern int cfg_product_has_smartantenna(void);

/*************************for device mode*******************************/
enum {
    DEVICE_MODE_FAT = 0, 
    DEVICE_MODE_FIT, 

    DEVICE_MODE_MAX
};

int cfg_get_device_mode(void);
int cfg_set_device_mode(int mode);

#ifdef __cplusplus
}
#endif

#endif
