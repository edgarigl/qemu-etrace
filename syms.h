/*
 * Copyright: 2013 Xilinx Inc
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA. 
 *
 */
#ifndef _SYMS_H
#define _SYMS_H

#include <stdint.h>
#include <stdlib.h>

/* A 64bit counter per 32bit word in the sym.  */
struct sym_coverage {
	uint64_t counter[0];
};

enum loc_flags {
	LOC_F_INLINED = (1 << 0),
};

struct sym_src_loc {
	struct sym_src_loc *next;
	const char *filename;
	unsigned int linenr;
	uint32_t flags;
};

struct sym_linemap {
	struct sym_src_loc locs[0];
};

struct sym
{
	struct sym *next;
	uint64_t addr;
	uint64_t size;
	int hits;
	uint64_t total_time;
	char *src_filename;

	struct sym_linemap *linemap;
	unsigned int maxline;
	struct sym_coverage *cov;

	/* For gcov, only counts entries no time.  */
	struct sym_coverage *cov_ent;
	int namelen;
	char name[128];
};

void sym_show_stats(void **store);
void sym_show(const char *prefix, const struct sym *s);
struct sym *sym_lookup_by_addr(void **rootp, uint64_t addr);
struct sym *sym_lookup_by_name(void **rootp, const char *name);
struct sym *sym_get_all(void **store, size_t *nr_syms);
struct sym *sym_get_unknown(void **store);
void sym_read_from_elf(void **rootp, char *nm, char *elf);
void sym_build_linemap(void **rootp, const char *addr2line, const char *elf);
void sym_update_cov(struct sym *sym, uint64_t start, uint64_t end,
			uint32_t time);

#endif
