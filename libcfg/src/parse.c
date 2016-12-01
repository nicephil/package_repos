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

#include <string.h>
#include <stdint.h>

#include "cfg/cfg.h"

void cfg_parse_section(struct cfg_section *s, const struct cfg_parse_option *opts,
		       int n_opts, struct cfg_option **tb)
{
	struct cfg_element *e;

	memset(tb, 0, n_opts * sizeof(*tb));

	cfg_foreach_element(&s->options, e) {
		struct cfg_option *o = cfg_to_option(e);
		int i;

		for (i = 0; i < n_opts; i++) {
			if (tb[i])
				continue;

			if (strcmp(opts[i].name, o->e.name) != 0)
				continue;

			if (opts[i].type != o->type)
				continue;

			/* match found */
			tb[i] = o;
			break;
		}
	}
}

//-----------------------------------------------------------------------------
// MurmurHashNeutral2, by Austin Appleby

// Same as MurmurHash2, but endian- and alignment-neutral.
static uint32_t hash_murmur2(uint32_t h, const void * key, int len)
{
	const unsigned char * data = key;
	const uint32_t m = 0x5bd1e995;
	const int r = 24;

	while(len >= 4)
	{
		unsigned int k;

		k  = data[0];
		k |= data[1] << 8;
		k |= data[2] << 16;
		k |= data[3] << 24;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	switch(len)
	{
	case 3: h ^= data[2] << 16;
	case 2: h ^= data[1] << 8;
	case 1: h ^= data[0];
	        h *= m;
	};

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

static uint32_t cfg_hash_list(uint32_t h, const struct cfg_list *list)
{
	const struct cfg_element *e;

	cfg_foreach_element(list, e) {
		h = hash_murmur2(h, e->name, strlen(e->name) + 1);
	}
	return h;
}

uint32_t cfg_hash_options(struct cfg_option **tb, int n_opts)
{
	uint32_t h = 0xdeadc0de;
	int i;

	for (i = 0; i < n_opts; i++) {
		const struct cfg_option *o = tb[i];

		if (!tb[i])
			continue;

		h = hash_murmur2(h, o->e.name, strlen(o->e.name) + 1);
		h = hash_murmur2(h, &o->type, sizeof(o->type));

		switch (tb[i]->type) {
		case CFG_TYPE_STRING:
			h = hash_murmur2(h, o->v.string, strlen(o->v.string) + 1);
			break;
		case CFG_TYPE_LIST:
			h = cfg_hash_list(h, &o->v.list);
			break;
		}
	}

	return h;
}


