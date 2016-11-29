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

static void cfg_list_set_pos(struct cfg_list *head, struct cfg_list *ptr, int pos)
{
	struct cfg_list *new_head = head;
	struct cfg_element *p = NULL;

	cfg_list_del(ptr);
	cfg_foreach_element(head, p) {
		if (pos-- <= 0)
			break;
		new_head = &p->list;
	}

	cfg_list_add(new_head->next, ptr);
}

static inline void cfg_list_fixup(struct cfg_list *ptr)
{
	ptr->prev->next = ptr;
	ptr->next->prev = ptr;
}

/*
 * cfg_alloc_generic allocates a new cfg_element with payload
 * payload is appended to the struct to save memory and reduce fragmentation
 */
__private struct cfg_element *
cfg_alloc_generic(struct cfg_context *ctx, int type, const char *name, int size)
{
	struct cfg_element *e;
	int datalen = size;
	void *ptr;

	ptr = cfg_malloc(ctx, datalen);
	e = (struct cfg_element *) ptr;
	e->type = type;
	if (name) {
		CFG_TRAP_SAVE(ctx, error);
		e->name = cfg_strdup(ctx, name);
		CFG_TRAP_RESTORE(ctx);
	}
	cfg_list_init(&e->list);
	goto done;

error:
	free(ptr);
	CFG_THROW(ctx, ctx->err);

done:
	return e;
}

__private void
cfg_free_element(struct cfg_element *e)
{
	free(e->name);
	if (!cfg_list_empty(&e->list))
		cfg_list_del(&e->list);
	free(e);
}

static struct cfg_option *
cfg_alloc_option(struct cfg_section *s, const char *name, const char *value)
{
	struct cfg_package *p = s->package;
	struct cfg_context *ctx = p->ctx;
	struct cfg_option *o;

	o = cfg_alloc_element(ctx, option, name, strlen(value) + 1);
	o->type = CFG_TYPE_STRING;
	o->v.string = cfg_dataptr(o);
	o->section = s;
	strcpy(o->v.string, value);
	cfg_list_add(&s->options, &o->e.list);

	return o;
}

static inline void
cfg_free_option(struct cfg_option *o)
{
	struct cfg_element *e, *tmp;

	switch(o->type) {
	case CFG_TYPE_STRING:
		if ((o->v.string != cfg_dataptr(o)) &&
			(o->v.string != NULL))
			free(o->v.string);
		break;
	case CFG_TYPE_LIST:
		cfg_foreach_element_safe(&o->v.list, tmp, e) {
			cfg_free_element(e);
		}
		break;
	default:
		break;
	}
	cfg_free_element(&o->e);
}

static struct cfg_option *
cfg_alloc_list(struct cfg_section *s, const char *name)
{
	struct cfg_package *p = s->package;
	struct cfg_context *ctx = p->ctx;
	struct cfg_option *o;

	o = cfg_alloc_element(ctx, option, name, 0);
	o->type = CFG_TYPE_LIST;
	o->section = s;
	cfg_list_init(&o->v.list);
	cfg_list_add(&s->options, &o->e.list);

	return o;
}

/* Based on an efficient hash function published by D. J. Bernstein */
static unsigned int djbhash(unsigned int hash, char *str)
{
	int len = strlen(str);
	int i;

	/* initial value */
	if (hash == ~0)
		hash = 5381;

	for(i = 0; i < len; i++) {
		hash = ((hash << 5) + hash) + str[i];
	}
	return (hash & 0x7FFFFFFF);
}

/* fix up an unnamed section, e.g. after adding options to it */
__private void cfg_fixup_section(struct cfg_context *ctx, struct cfg_section *s)
{
	unsigned int hash = ~0;
	struct cfg_element *e;
	char buf[16];

	if (!s || s->e.name)
		return;

	/*
	 * Generate a name for unnamed sections. This is used as reference
	 * when locating or updating the section from apps/scripts.
	 * To make multiple concurrent versions somewhat safe for updating,
	 * the name is generated from a hash of its type and name/value
	 * pairs of its option, and it is prefixed by a counter value.
	 * If the order of the unnamed sections changes for some reason,
	 * updates to them will be rejected.
	 */
	hash = djbhash(hash, s->type);
	cfg_foreach_element(&s->options, e) {
		struct cfg_option *o;
		hash = djbhash(hash, e->name);
		o = cfg_to_option(e);
		switch(o->type) {
		case CFG_TYPE_STRING:
			hash = djbhash(hash, o->v.string);
			break;
		default:
			break;
		}
	}
	sprintf(buf, "cfg%02x%04x", ++s->package->n_section, hash % (1 << 16));
	s->e.name = cfg_strdup(ctx, buf);
}

static struct cfg_section *
cfg_alloc_section(struct cfg_package *p, const char *type, const char *name)
{
	struct cfg_context *ctx = p->ctx;
	struct cfg_section *s;

	if (name && !name[0])
		name = NULL;

	s = cfg_alloc_element(ctx, section, name, strlen(type) + 1);
	cfg_list_init(&s->options);
	s->type = cfg_dataptr(s);
	s->package = p;
	strcpy(s->type, type);
	if (name == NULL)
		s->anonymous = true;
	p->n_section++;

	cfg_list_add(&p->sections, &s->e.list);

	return s;
}

static void
cfg_free_section(struct cfg_section *s)
{
	struct cfg_element *o, *tmp;

	cfg_foreach_element_safe(&s->options, tmp, o) {
		cfg_free_option(cfg_to_option(o));
	}
	if ((s->type != cfg_dataptr(s)) &&
		(s->type != NULL))
		free(s->type);
	cfg_free_element(&s->e);
}

__private struct cfg_package *
cfg_alloc_package(struct cfg_context *ctx, const char *name)
{
	struct cfg_package *p;

	p = cfg_alloc_element(ctx, package, name, 0);
	p->ctx = ctx;
	cfg_list_init(&p->sections);
	cfg_list_init(&p->delta);
	cfg_list_init(&p->saved_delta);
	return p;
}

__private void
cfg_free_package(struct cfg_package **package)
{
	struct cfg_element *e, *tmp;
	struct cfg_package *p = *package;

	if(!p)
		return;

	free(p->path);
	cfg_foreach_element_safe(&p->sections, tmp, e) {
		cfg_free_section(cfg_to_section(e));
	}
	cfg_foreach_element_safe(&p->delta, tmp, e) {
		cfg_free_delta(cfg_to_delta(e));
	}
	cfg_foreach_element_safe(&p->saved_delta, tmp, e) {
		cfg_free_delta(cfg_to_delta(e));
	}
	cfg_free_element(&p->e);
	*package = NULL;
}

static void
cfg_free_any(struct cfg_element **e)
{
	switch((*e)->type) {
	case CFG_TYPE_SECTION:
		cfg_free_section(cfg_to_section(*e));
		break;
	case CFG_TYPE_OPTION:
		cfg_free_option(cfg_to_option(*e));
		break;
	default:
		break;
	}
	*e = NULL;
}

__private struct cfg_element *
cfg_lookup_list(struct cfg_list *list, const char *name)
{
	struct cfg_element *e;

	cfg_foreach_element(list, e) {
		if (!strcmp(e->name, name))
			return e;
	}
	return NULL;
}

static struct cfg_element *
cfg_lookup_ext_section(struct cfg_context *ctx, struct cfg_ptr *ptr)
{
	char *idxstr, *t, *section, *name;
	struct cfg_element *e = NULL;
	struct cfg_section *s;
	int idx, c;

	section = cfg_strdup(ctx, ptr->section);
	name = idxstr = section + 1;

	if (section[0] != '@')
		goto error;

	/* parse the section index part */
	idxstr = strchr(idxstr, '[');
	if (!idxstr)
		goto error;
	*idxstr = 0;
	idxstr++;

	t = strchr(idxstr, ']');
	if (!t)
		goto error;
	if (t[1] != 0)
		goto error;
	*t = 0;

	t = NULL;
	idx = strtol(idxstr, &t, 10);
	if (t && *t)
		goto error;

	if (!*name)
		name = NULL;
	else if (!cfg_validate_type(name))
		goto error;

	/* if the given index is negative, it specifies the section number from
	 * the end of the list */
	if (idx < 0) {
		c = 0;
		cfg_foreach_element(&ptr->p->sections, e) {
			s = cfg_to_section(e);
			if (name && (strcmp(s->type, name) != 0))
				continue;

			c++;
		}
		idx += c;
	}

	c = 0;
	cfg_foreach_element(&ptr->p->sections, e) {
		s = cfg_to_section(e);
		if (name && (strcmp(s->type, name) != 0))
			continue;

		if (idx == c)
			goto done;
		c++;
	}
	e = NULL;
	goto done;

error:
	e = NULL;
	memset(ptr, 0, sizeof(struct cfg_ptr));
	CFG_THROW(ctx, CFG_ERR_INVAL);
done:
	free(section);
	if (e)
		ptr->section = e->name;
	return e;
}

int
cfg_lookup_next(struct cfg_context *ctx, struct cfg_element **e, struct cfg_list *list, const char *name)
{
	CFG_HANDLE_ERR(ctx);

	*e = cfg_lookup_list(list, name);
	if (!*e)
		CFG_THROW(ctx, CFG_ERR_NOTFOUND);

	return 0;
}

int
cfg_lookup_ptr(struct cfg_context *ctx, struct cfg_ptr *ptr, char *str, bool extended)
{
	struct cfg_element *e;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, ptr != NULL);

	if (str)
		CFG_INTERNAL(cfg_parse_ptr, ctx, ptr, str);

	ptr->flags |= CFG_LOOKUP_DONE;

	/* look up the package first */
	if (ptr->p)
		e = &ptr->p->e;
	else
		e = cfg_lookup_list(&ctx->root, ptr->package);

	if (!e) {
		CFG_INTERNAL(cfg_load, ctx, ptr->package, &ptr->p);
		if (!ptr->p)
			goto notfound;
		ptr->last = &ptr->p->e;
	} else {
		ptr->p = cfg_to_package(e);
		ptr->last = e;
	}

	if (!ptr->section && !ptr->s)
		goto complete;

	/* if the section name validates as a regular name, pass through
	 * to the regular cfg_lookup function call */
	if (ptr->s) {
		e = &ptr->s->e;
	} else if (ptr->flags & CFG_LOOKUP_EXTENDED) {
		if (extended)
			e = cfg_lookup_ext_section(ctx, ptr);
		else
			CFG_THROW(ctx, CFG_ERR_INVAL);
	} else {
		e = cfg_lookup_list(&ptr->p->sections, ptr->section);
	}

	if (!e)
		goto abort;

	ptr->last = e;
	ptr->s = cfg_to_section(e);

	if (ptr->option) {
		e = cfg_lookup_list(&ptr->s->options, ptr->option);
		if (!e)
			goto abort;

		ptr->o = cfg_to_option(e);
		ptr->last = e;
	}

complete:
	ptr->flags |= CFG_LOOKUP_COMPLETE;
abort:
	return 0;

notfound:
	CFG_THROW(ctx, CFG_ERR_NOTFOUND);
	return 0;
}

__private struct cfg_element *
cfg_expand_ptr(struct cfg_context *ctx, struct cfg_ptr *ptr, bool complete)
{
	CFG_ASSERT(ctx, ptr != NULL);

	if (!(ptr->flags & CFG_LOOKUP_DONE))
		CFG_INTERNAL(cfg_lookup_ptr, ctx, ptr, NULL, 1);
	if (complete && !(ptr->flags & CFG_LOOKUP_COMPLETE))
		CFG_THROW(ctx, CFG_ERR_NOTFOUND);
	CFG_ASSERT(ctx, ptr->p != NULL);

	/* fill in missing string info */
	if (ptr->p && !ptr->package)
		ptr->package = ptr->p->e.name;
	if (ptr->s && !ptr->section)
		ptr->section = ptr->s->e.name;
	if (ptr->o && !ptr->option)
		ptr->option = ptr->o->e.name;

	if (ptr->o)
		return &ptr->o->e;
	if (ptr->s)
		return &ptr->s->e;
	if (ptr->p)
		return &ptr->p->e;
	else
		return NULL;
}

static void cfg_add_element_list(struct cfg_context *ctx, struct cfg_ptr *ptr, bool internal)
{
	struct cfg_element *e;
	struct cfg_package *p;

	p = ptr->p;
	if (!internal && p->has_delta)
		cfg_add_delta(ctx, &p->delta, CFG_CMD_LIST_ADD, ptr->section, ptr->option, ptr->value);

	e = cfg_alloc_generic(ctx, CFG_TYPE_ITEM, ptr->value, sizeof(struct cfg_option));
	cfg_list_add(&ptr->o->v.list, &e->list);
}

int cfg_rename(struct cfg_context *ctx, struct cfg_ptr *ptr)
{
	/* NB: CFG_INTERNAL use means without delta tracking */
	bool internal = ctx && ctx->internal;
	struct cfg_element *e;
	struct cfg_package *p;
	char *n;

	CFG_HANDLE_ERR(ctx);

	e = cfg_expand_ptr(ctx, ptr, true);
	p = ptr->p;

	CFG_ASSERT(ctx, ptr->s);
	CFG_ASSERT(ctx, ptr->value);

	if (!internal && p->has_delta)
		cfg_add_delta(ctx, &p->delta, CFG_CMD_RENAME, ptr->section, ptr->option, ptr->value);

	n = cfg_strdup(ctx, ptr->value);
	free(e->name);
	e->name = n;

	if (e->type == CFG_TYPE_SECTION)
		cfg_to_section(e)->anonymous = false;

	return 0;
}

int cfg_reorder_section(struct cfg_context *ctx, struct cfg_section *s, int pos)
{
	struct cfg_package *p = s->package;
	bool internal = ctx && ctx->internal;
	char order[32];

	CFG_HANDLE_ERR(ctx);

	cfg_list_set_pos(&s->package->sections, &s->e.list, pos);
	if (!internal && p->has_delta) {
		sprintf(order, "%d", pos);
		cfg_add_delta(ctx, &p->delta, CFG_CMD_REORDER, s->e.name, NULL, order);
	}

	return 0;
}

int cfg_add_section(struct cfg_context *ctx, struct cfg_package *p, const char *type, struct cfg_section **res)
{
	bool internal = ctx && ctx->internal;
	struct cfg_section *s;

	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, p != NULL);
	s = cfg_alloc_section(p, type, NULL);
	cfg_fixup_section(ctx, s);
	*res = s;
	if (!internal && p->has_delta)
		cfg_add_delta(ctx, &p->delta, CFG_CMD_ADD, s->e.name, NULL, type);

	return 0;
}

int cfg_delete(struct cfg_context *ctx, struct cfg_ptr *ptr)
{
	/* NB: pass on internal flag to cfg_del_element */
	bool internal = ctx && ctx->internal;
	struct cfg_package *p;
	struct cfg_element *e1, *e2, *tmp;
	int index;

	CFG_HANDLE_ERR(ctx);

	e1 = cfg_expand_ptr(ctx, ptr, true);
	p = ptr->p;

	CFG_ASSERT(ctx, ptr->s);

	if (ptr->o && ptr->o->type == CFG_TYPE_LIST && ptr->value && *ptr->value) {
		if (!sscanf(ptr->value, "%d", &index))
			return 1;

		cfg_foreach_element_safe(&ptr->o->v.list, tmp, e2) {
			if (index == 0) {
				if (!internal && p->has_delta)
					cfg_add_delta(ctx, &p->delta, CFG_CMD_REMOVE, ptr->section, ptr->option, ptr->value);
				cfg_free_option(cfg_to_option(e2));
				return 0;
			}
			index--;
		}

		return 0;
	}

	if (!internal && p->has_delta)
		cfg_add_delta(ctx, &p->delta, CFG_CMD_REMOVE, ptr->section, ptr->option, NULL);

	cfg_free_any(&e1);

	if (ptr->option)
		ptr->o = NULL;
	else if (ptr->section)
		ptr->s = NULL;

	return 0;
}

int cfg_add_list(struct cfg_context *ctx, struct cfg_ptr *ptr)
{
	/* NB: CFG_INTERNAL use means without delta tracking */
	bool internal = ctx && ctx->internal;
	struct cfg_option *prev = NULL;
	const char *value2 = NULL;

	CFG_HANDLE_ERR(ctx);

	cfg_expand_ptr(ctx, ptr, false);
	CFG_ASSERT(ctx, ptr->s);
	CFG_ASSERT(ctx, ptr->value);

	if (ptr->o) {
		switch (ptr->o->type) {
		case CFG_TYPE_STRING:
			/* we already have a string value, convert that to a list */
			prev = ptr->o;
			value2 = ptr->value;
			ptr->value = ptr->o->v.string;
			break;
		case CFG_TYPE_LIST:
			cfg_add_element_list(ctx, ptr, internal);
			return 0;
		default:
			CFG_THROW(ctx, CFG_ERR_INVAL);
			break;
		}
	}

	ptr->o = cfg_alloc_list(ptr->s, ptr->option);
	if (prev) {
		cfg_add_element_list(ctx, ptr, true);
		cfg_free_option(prev);
		ptr->value = value2;
	}
	cfg_add_element_list(ctx, ptr, internal);

	return 0;
}

int cfg_del_list(struct cfg_context *ctx, struct cfg_ptr *ptr)
{
	/* NB: pass on internal flag to cfg_del_element */
	bool internal = ctx && ctx->internal;
	struct cfg_element *e, *tmp;
	struct cfg_package *p;

	CFG_HANDLE_ERR(ctx);

	cfg_expand_ptr(ctx, ptr, false);
	CFG_ASSERT(ctx, ptr->s);
	CFG_ASSERT(ctx, ptr->value);

	if (!(ptr->o && ptr->option))
		return 0;

	if ((ptr->o->type != CFG_TYPE_LIST))
		return 0;

	p = ptr->p;
	if (!internal && p->has_delta)
		cfg_add_delta(ctx, &p->delta, CFG_CMD_LIST_DEL, ptr->section, ptr->option, ptr->value);

	cfg_foreach_element_safe(&ptr->o->v.list, tmp, e) {
		if (!strcmp(ptr->value, cfg_to_option(e)->e.name)) {
			cfg_free_option(cfg_to_option(e));
		}
	}

	return 0;
}

int cfg_set(struct cfg_context *ctx, struct cfg_ptr *ptr)
{
	/* NB: CFG_INTERNAL use means without delta tracking */
	bool internal = ctx && ctx->internal;

	CFG_HANDLE_ERR(ctx);
	cfg_expand_ptr(ctx, ptr, false);
	CFG_ASSERT(ctx, ptr->value);
	CFG_ASSERT(ctx, ptr->s || (!ptr->option && ptr->section));
	if (!ptr->option && ptr->value[0]) {
		CFG_ASSERT(ctx, cfg_validate_type(ptr->value));
	}

	if (!ptr->o && ptr->s && ptr->option) {
		struct cfg_element *e;
		e = cfg_lookup_list(&ptr->s->options, ptr->option);
		if (e)
			ptr->o = cfg_to_option(e);
	}
	if (!ptr->value[0]) {
		/* if setting a nonexistant option/section to a nonexistant value,
		 * exit without errors */
		if (!(ptr->flags & CFG_LOOKUP_COMPLETE))
			return 0;

		return cfg_delete(ctx, ptr);
	} else if (!ptr->o && ptr->option) { /* new option */
		ptr->o = cfg_alloc_option(ptr->s, ptr->option, ptr->value);
		ptr->last = &ptr->o->e;
	} else if (!ptr->s && ptr->section) { /* new section */
		ptr->s = cfg_alloc_section(ptr->p, ptr->value, ptr->section);
		ptr->last = &ptr->s->e;
	} else if (ptr->o && ptr->option) { /* update option */
		if ((ptr->o->type == CFG_TYPE_STRING) &&
			!strcmp(ptr->o->v.string, ptr->value))
			return 0;
		cfg_free_option(ptr->o);
		ptr->o = cfg_alloc_option(ptr->s, ptr->option, ptr->value);
		ptr->last = &ptr->o->e;
	} else if (ptr->s && ptr->section) { /* update section */
		char *s = cfg_strdup(ctx, ptr->value);

		if (ptr->s->type == cfg_dataptr(ptr->s)) {
			ptr->last = NULL;
			ptr->last = cfg_realloc(ctx, ptr->s, sizeof(struct cfg_section));
			ptr->s = cfg_to_section(ptr->last);
			cfg_list_fixup(&ptr->s->e.list);
		} else {
			free(ptr->s->type);
		}
		ptr->s->type = s;
	} else {
		CFG_THROW(ctx, CFG_ERR_INVAL);
	}

	if (!internal && ptr->p->has_delta)
		cfg_add_delta(ctx, &ptr->p->delta, CFG_CMD_CHANGE, ptr->section, ptr->option, ptr->value);

	return 0;
}

int cfg_unload(struct cfg_context *ctx, struct cfg_package *p)
{
	CFG_HANDLE_ERR(ctx);
	CFG_ASSERT(ctx, p != NULL);

	cfg_free_package(&p);
	return 0;
}

