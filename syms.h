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

/* A 64-bit counter for each byte in the symbol.  */
struct sym_coverage {
	uint64_t counter[0];
};

enum loc_flags {
	LOC_F_INLINED = (1 << 0),
	LOC_F_STMT = (1 << 1),
};

enum sym_flags {
	SYM_F_EXPLICIT_SIZE = (1 << 0),
	SYM_F_INFERRED_SIZE = (1 << 1),
	SYM_F_FUNCTION = (1 << 2),
	SYM_F_EXECUTABLE = (1 << 3),
	SYM_F_LOCAL = (1 << 4),
	SYM_F_GLOBAL = (1 << 5),
	SYM_F_WEAK = (1 << 6),
};

struct sym_src_loc {
	struct sym_src_loc *next;
	const char *filename;
	unsigned int linenr;
	unsigned int column;
	unsigned int discriminator;
	uint32_t flags;
};

struct sym_linemap {
	struct sym_src_loc locs[0];
};

struct sym_source_range {
	uint64_t start;
	uint64_t end;
	struct sym_src_loc *locs;
};

struct sym_load_segment {
	uint64_t linked_start;
	uint64_t image_start;
	uint64_t file_size;
	uint64_t memory_size;
};

struct sym
{
	struct sym *next;
	uint64_t addr;
	uint64_t size;
	uint64_t section_start;
	uint64_t section_end;
	const char *section_name;
	uint32_t flags;
	int hits;
	uint64_t total_time;
	char *src_filename;

	struct sym_linemap *linemap;
	unsigned int maxline;
	struct sym_coverage *cov;

	/* For gcov, only counts entries no time.  */
	struct sym_coverage *cov_ent;
	uint64_t source_hits;
	struct sym_src_loc declaration;
	bool declaration_ambiguous;
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
void sym_build_linemap(void **rootp, const char *dwarfdump, const char *elf);
void sym_build_source_coverage(void **rootp, const char *addr2line,
			       const char *dwarfdump, const char *objdump,
			       const char *elf);
void sym_update_cov(struct sym *sym, uint64_t start, uint64_t end,
			uint64_t time, uint64_t count);
void sym_update_image_cov(void **store, uint64_t start, uint64_t end,
			  uint64_t count);
uint64_t sym_image_coverage_at(void **store, uint64_t addr);
bool sym_address_is_executable(void **store, uint64_t addr);
bool sym_range_is_executable(void **store, uint64_t start, uint64_t end);
bool sym_code_matches(void **store, uint64_t addr,
		      const uint8_t *code, size_t len);
size_t sym_x86_alt_patch_span(void **store, uint64_t addr,
			       const uint8_t *code, size_t len);
bool sym_instruction_matches(void **store, uint64_t addr,
			     const uint8_t *code, size_t len);
size_t sym_find_code_matches(void **store, const uint8_t *code, size_t len,
			     uint64_t *matches, size_t capacity);
const struct sym_source_range *sym_get_source_ranges(void **store,
						      size_t *nr_ranges);
const struct sym_load_segment *sym_get_executable_load_segments(
	void **store, size_t *nr_segments);
uint16_t sym_get_elf_machine(void **store);
const char *sym_get_machine_name(void **store);

#endif
