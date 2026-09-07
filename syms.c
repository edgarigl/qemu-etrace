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
#define _GNU_SOURCE
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <search.h>

#include "config.h"
#include "filename.h"
#include "dwarf-lines.h"
#include "util.h"
#include "safeio.h"
#include "syms.h"
#include "run.h"

#include "bfd.h"

#define LOOKUP_STATS 0
#if LOOKUP_STATS
#define LOOKUP_STATSD(x) x
#else
#define LOOKUP_STATSD(x)
#endif

struct sym_store {
	uint64_t min, max;
	char *elf_filename;
	bool image_data_loaded;
	/* Binary tree for fast name lookups.  */
	void *rootp;

	struct sym *allsyms;
	struct sym unknown; /* e.g, user-space when profiling the kernel  */

	/* 4 entries seem to do a good job.  */
	struct sym *last[4];

	unsigned int nr_stored;

	unsigned int nr_flush;
	unsigned int hits_l[3];
	unsigned int misses;

	struct sym_source_range *line_ranges;
	size_t nr_line_ranges;

	struct image_section {
		uint64_t start;
		uint64_t end;
		char *name;
		uint8_t *data;
		struct sym_coverage *cov;
	} *sections;
	size_t nr_sections;
};

void sym_show(const char *prefix, const struct sym *s)
{
	printf("%s:%p name=%s addr=%" PRIx64 " size=%" PRIx64 "\n",
	       prefix, s, s->name, s->addr, s->size);
}

void sym_show_stats(void **store)
{
	struct sym_store *ss = *store;
	unsigned int i;

	if (!LOOKUP_STATS)
		return;

	for (i = 0; i < sizeof ss->hits_l / sizeof ss->hits_l[0]; i++) {
		printf("l%u hits %u\n", i, ss->hits_l[i]);
	}
	printf("misses %u\n", ss->misses);
	printf("flushes %u\n", ss->nr_flush);
	printf("nr_stored %u\n", ss->nr_stored);
}

struct sym *sym_get_all(void **store, size_t *nr_syms)
{
	struct sym_store *ss = *store;
	if (!ss)
		return NULL;

	*nr_syms = ss->nr_stored;
	return ss->allsyms;
}

static inline int sym_find(const void *pa, const void *pb)
{
	uint64_t addr = *(uint64_t *) pa;
	const struct sym *sb = pb;
	uint64_t sb_end = sb->size > UINT64_MAX - sb->addr
		? UINT64_MAX : sb->addr + sb->size;

	if (addr < sb->addr)
		return -1;
	else if (addr >= sb_end)
		return 1;
	return 0;
}

int sym_str_compare(const void *pa, const void *pb)
{
	const struct sym *sa = pa, *sb = pb;
	int lendiff;
	int r;

	lendiff = sa->namelen - sb->namelen;
	if (lendiff)
		r = lendiff;
	else
		r = strcmp(sa->name, sb->name);
	if (0) {
		printf("sym_str_compare %d\n", r);
		sym_show("sa", sa);
		sym_show("sb", sb);
	}

	return r;
}

int sym_compare(const void *pa, const void *pb)
{
	const struct sym *sa = pa, *sb = pb;
	int r;

	if (sa->addr < sb->addr)
		r = -1;
	else if (sa->addr > sb->addr)
		r = 1;
	else {
		/* Aliases end up here..  */
		r = 0;
	}

	if (0) {
		printf("sym_compare %d\n", r);
		sym_show("sa", sa);
		sym_show("sb", sb);
	}

	return r;
}

static inline void sym_push_last(struct sym_store *ss, struct sym *sym)
{
	unsigned int i;
	for (i = (sizeof ss->last / sizeof ss->last[0]) - 1; i > 0; i--) {
		ss->last[i] = ss->last[i - 1];
	}
	ss->last[0] = sym;
}

static struct sym *sym_last_lookup(struct sym_store *ss, uint64_t addr)
{
	int i;

	for (i = 0; i < (sizeof ss->last / sizeof ss->last[0]); i++) {
		if (!ss->last[i])
			break;
		if (sym_find(&addr, ss->last[i]) == 0) {
			return ss->last[i];
		}
	}
	return NULL;
}

struct sym *sym_get_unknown(void **store)
{
	struct sym_store *ss = *store;
	if (!ss)
		return NULL;
	return &ss->unknown;
}

struct sym *sym_lookup_by_name(void **store, const char *name)
{
	struct sym **s;
	struct sym_store *ss = *store;
	struct sym search;

	memset(&search, 0, sizeof search);
	search.namelen = strlen(name);
	assert(name);
	assert(search.namelen > 0);
	memcpy(&search.name[0], name, search.namelen + 1);
	s = tfind(&search, &ss->rootp, sym_str_compare);
	return s ? *s : NULL;
}

struct sym *sym_lookup_by_addr(void **store, uint64_t addr)
{
	struct sym_store *ss = *store;
	struct sym *symp;

	if (addr < ss->min || addr >= ss->max) {
		return NULL;
	}

	symp = sym_last_lookup(ss, addr);
	if (symp) {
		LOOKUP_STATSD(ss->hits_l[0]++);
		return symp;
	}

	symp = bsearch(&addr, ss->allsyms,
                    ss->nr_stored, sizeof ss->allsyms[0], sym_find);
	if (symp) {
		sym_push_last(ss, symp);
		LOOKUP_STATSD(ss->hits_l[2]++);
		return symp;
	}

	LOOKUP_STATSD(ss->misses++);
	return NULL;
}

static void sym_alloc_cov(struct sym *sym)
{
	size_t nr_entries = sym->size + 1;
	sym->cov = safe_mallocz(sizeof sym->cov->counter[0] * nr_entries);
	sym->cov_ent = safe_mallocz(sizeof sym->cov_ent->counter[0] * nr_entries);
}

static void sym_alloc_linemap(struct sym *sym)
{
	size_t nr_entries = sym->size + 1;
	sym->linemap = safe_mallocz(sizeof sym->linemap->locs[0] * nr_entries);
}

static struct sym_src_loc *new_source_loc(const char *filename,
					  unsigned int linenr,
					  unsigned int discriminator,
					  uint32_t flags)
{
	struct sym_src_loc *loc = safe_mallocz(sizeof(*loc));

	loc->filename = strdup(filename);
	loc->linenr = linenr;
	loc->discriminator = discriminator;
	loc->flags = flags;
	return loc;
}

static void append_source_loc(struct sym_src_loc **head,
			      struct sym_src_loc *new_loc)
{
	struct sym_src_loc **tail = head;

	while (*tail)
		tail = &(*tail)->next;
	*tail = new_loc;
}

static void free_source_locs(struct sym_src_loc *loc)
{
	while (loc) {
		struct sym_src_loc *next = loc->next;

		free((void *)loc->filename);
		free(loc);
		loc = next;
	}
}

static void add_line_range(struct sym_store *ss, uint64_t start, uint64_t end,
			   struct sym_src_loc *locs)
{
	struct sym_source_range *range;

	if (end <= start) {
		free_source_locs(locs);
		return;
	}
	ss->line_ranges = safe_realloc(ss->line_ranges,
		(sizeof(*ss->line_ranges) * (ss->nr_line_ranges + 1)));
	range = &ss->line_ranges[ss->nr_line_ranges++];
	range->start = start;
	range->end = end;
	range->locs = locs;
}

static int line_range_compare(const void *a, const void *b)
{
	const struct sym_source_range *ra = a;
	const struct sym_source_range *rb = b;

	if (ra->start < rb->start)
		return -1;
	if (ra->start > rb->start)
		return 1;
	if (ra->end < rb->end)
		return -1;
	if (ra->end > rb->end)
		return 1;
	return 0;
}

static void sym_add_source_loc(struct sym *sym, uint64_t offset,
			       const struct sym_src_loc *source)
{
	struct sym_src_loc *loc;

	if (!sym->src_filename)
		sym->src_filename = strdup(source->filename);
	if (!sym->linemap)
		sym_alloc_linemap(sym);
	if (source->linenr >= sym->maxline)
		sym->maxline = source->linenr;

	loc = &sym->linemap->locs[offset];
	if (loc->filename) {
		while (loc->next)
			loc = loc->next;
		loc->next = safe_mallocz(sizeof(*loc));
		loc = loc->next;
	}
	loc->filename = source->filename;
	loc->linenr = source->linenr;
	loc->discriminator = source->discriminator;
	loc->flags = source->flags;
}

static void materialize_line_ranges(struct sym_store *ss)
{
	size_t i;

	if (!ss->nr_line_ranges)
		return;
	qsort(ss->line_ranges, ss->nr_line_ranges,
	      sizeof(*ss->line_ranges), line_range_compare);
	for (i = 0; i < ss->nr_line_ranges; i++) {
		struct sym_source_range *range = &ss->line_ranges[i];
		size_t high = ss->nr_stored;
		size_t low = 0;
		size_t j;

		while (low < high) {
			size_t mid = low + (high - low) / 2;

			if (ss->allsyms[mid].addr < range->start)
				low = mid + 1;
			else
				high = mid;
		}
		if (low > 0)
			low--;
		while (low > 0
		       && ss->allsyms[low - 1].addr == ss->allsyms[low].addr)
			low--;

		for (j = low; j < ss->nr_stored; j++) {
			struct sym *sym = &ss->allsyms[j];
			uint64_t sym_end;
			uint64_t end;
			uint64_t start;
			uint64_t addr;
			struct sym_src_loc *source;

			if (sym->addr >= range->end)
				break;
			if (!sym->size)
				continue;
			sym_end = sym->size > UINT64_MAX - sym->addr
				? UINT64_MAX : sym->addr + sym->size;
			if (sym_end <= range->start)
				continue;
			start = range->start > sym->addr
				? range->start : sym->addr;
			end = range->end < sym_end ? range->end : sym_end;
			for (addr = start; addr < end; addr++) {
				for (source = range->locs; source;
				     source = source->next)
					sym_add_source_loc(sym, addr - sym->addr,
							   source);
			}
		}
	}
}

const struct sym_source_range *sym_get_source_ranges(void **store,
						      size_t *nr_ranges)
{
	struct sym_store *ss = *store;

	if (!ss) {
		*nr_ranges = 0;
		return NULL;
	}
	*nr_ranges = ss->nr_line_ranges;
	return ss->line_ranges;
}

static int image_section_compare(const void *a, const void *b)
{
	const struct image_section *sa = a;
	const struct image_section *sb = b;

	if (sa->start < sb->start)
		return -1;
	if (sa->start > sb->start)
		return 1;
	return 0;
}

static struct image_section *image_section_find(struct sym_store *ss,
						 uint64_t addr)
{
	size_t high = ss->nr_sections;
	size_t low = 0;

	while (low < high) {
		size_t mid = low + (high - low) / 2;
		struct image_section *section = &ss->sections[mid];

		if (addr < section->start) {
			high = mid;
		} else if (addr >= section->end) {
			low = mid + 1;
		} else {
			return section;
		}
	}
	return NULL;
}

static uint64_t next_image_section_start(struct sym_store *ss, uint64_t addr)
{
	size_t high = ss->nr_sections;
	size_t low = 0;

	while (low < high) {
		size_t mid = low + (high - low) / 2;

		if (ss->sections[mid].start <= addr)
			low = mid + 1;
		else
			high = mid;
	}
	return low < ss->nr_sections ? ss->sections[low].start : UINT64_MAX;
}

static struct sym *find_bfd_symbol(struct sym_store *ss, const char *name,
				   uint64_t addr)
{
	void *store = ss;
	struct sym *sym;
	size_t high = ss->nr_stored;
	size_t low = 0;
	size_t first;
	size_t count = 0;

	if (name && *name) {
		sym = sym_lookup_by_name(&store, name);
		if (sym && sym->addr == addr)
			return sym;
	}

	while (low < high) {
		size_t mid = low + (high - low) / 2;

		if (ss->allsyms[mid].addr < addr)
			low = mid + 1;
		else
			high = mid;
	}
	first = low;
	while (low < ss->nr_stored && ss->allsyms[low].addr == addr) {
		sym = &ss->allsyms[low++];
		if (name && !strcmp(sym->name, name))
			return sym;
		count++;
	}
	return count == 1 ? &ss->allsyms[first] : NULL;
}

static void read_bfd_symbol_table(struct sym_store *ss, bfd *abfd,
				  bool dynamic)
{
	asymbol **symbols;
	long storage;
	long count;
	long i;

	storage = dynamic ? bfd_get_dynamic_symtab_upper_bound(abfd)
		: bfd_get_symtab_upper_bound(abfd);
	if (storage <= 0)
		return;
	symbols = safe_malloc(storage);
	count = dynamic ? bfd_canonicalize_dynamic_symtab(abfd, symbols)
		: bfd_canonicalize_symtab(abfd, symbols);
	if (count < 0) {
		fprintf(stderr, "Unable to read ELF symbols: %s\n",
			bfd_errmsg(bfd_get_error()));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < count; i++) {
		asymbol *bfd_sym = symbols[i];
		struct sym *sym;

		if (!(bfd_sym->flags & BSF_FUNCTION))
			continue;
		sym = find_bfd_symbol(ss, bfd_asymbol_name(bfd_sym),
				      bfd_asymbol_value(bfd_sym));
		if (sym)
			sym->flags |= SYM_F_FUNCTION;
	}
	free(symbols);
}

static void infer_function_sizes(struct sym_store *ss)
{
	size_t i;

	for (i = 0; i < ss->nr_stored; i++) {
		struct sym *sym = &ss->allsyms[i];
		bool has_alias = false;
		uint64_t end;
		size_t j;

		if (sym->size || !(sym->flags & SYM_F_FUNCTION)
		    || !(sym->flags & SYM_F_EXECUTABLE))
			continue;

		for (j = 0; j < ss->nr_stored; j++) {
			if (j != i && ss->allsyms[j].addr == sym->addr) {
				has_alias = true;
				break;
			}
		}
		if (has_alias)
			continue;

		end = sym->section_end;
		for (j = 0; j < ss->nr_stored; j++) {
			struct sym *next = &ss->allsyms[j];

			if (next->addr > sym->addr && next->addr < end
			    && next->section_start == sym->section_start)
				end = next->addr;
		}
		if (end > sym->addr) {
			sym->size = end - sym->addr;
			sym->flags |= SYM_F_INFERRED_SIZE;
		}
	}
}

static void read_executable_sections(struct sym_store *ss, const char *elf)
{
	asection *section;
	bfd *abfd;
	size_t i;

	free(ss->elf_filename);
	ss->elf_filename = strdup(elf);
	abfd = bfd_openr(elf, NULL);
	if (!abfd || !bfd_check_format(abfd, bfd_object)) {
		fprintf(stderr, "Unable to read ELF sections from %s: %s\n",
			elf, bfd_errmsg(bfd_get_error()));
		exit(EXIT_FAILURE);
	}

	for (section = abfd->sections; section; section = section->next) {
		flagword flags = bfd_section_flags(section);
		bfd_size_type size = bfd_section_size(section);
		bfd_vma start = bfd_section_vma(section);
		struct image_section *image;

		if (!(flags & SEC_ALLOC) || !(flags & SEC_CODE) || !size)
			continue;
		if (size > UINT64_MAX - start) {
			fprintf(stderr, "Executable ELF section address overflow\n");
			exit(EXIT_FAILURE);
		}
		ss->sections = safe_realloc(ss->sections,
			(sizeof(*ss->sections) * (ss->nr_sections + 1)));
		image = &ss->sections[ss->nr_sections++];
		image->start = start;
		image->end = start + size;
		image->name = strdup(bfd_section_name(section));
		image->cov = NULL;
	}
	qsort(ss->sections, ss->nr_sections, sizeof(*ss->sections),
	      image_section_compare);
	for (i = 1; i < ss->nr_sections; i++) {
		if (ss->sections[i].start < ss->sections[i - 1].end) {
			fprintf(stderr, "Overlapping executable ELF sections\n");
			exit(EXIT_FAILURE);
		}
	}
	for (i = 0; i < ss->nr_stored; i++) {
		struct image_section *image;

		image = image_section_find(ss, ss->allsyms[i].addr);
		if (!image)
			continue;
		ss->allsyms[i].flags |= SYM_F_EXECUTABLE;
		ss->allsyms[i].section_start = image->start;
		ss->allsyms[i].section_end = image->end;
		ss->allsyms[i].section_name = image->name;
	}
	read_bfd_symbol_table(ss, abfd, false);
	read_bfd_symbol_table(ss, abfd, true);
	infer_function_sizes(ss);
	for (i = 0; i < ss->nr_stored; i++) {
		struct sym *sym = &ss->allsyms[i];
		uint64_t end = sym->size > UINT64_MAX - sym->addr
			? UINT64_MAX : sym->addr + sym->size;

		if (end > ss->max)
			ss->max = end;
	}
	bfd_close(abfd);
}

bool sym_address_is_executable(void **store, uint64_t addr)
{
	struct sym_store *ss = *store;

	return ss && image_section_find(ss, addr);
}

bool sym_range_is_executable(void **store, uint64_t start, uint64_t end)
{
	struct sym_store *ss = *store;
	struct image_section *section;

	if (!ss || end <= start)
		return false;
	section = image_section_find(ss, start);
	return section && end <= section->end;
}

static bool load_image_data(struct sym_store *ss)
{
	bfd *abfd;
	asection *section;
	size_t loaded = 0;

	if (ss->image_data_loaded)
		return true;
	if (!ss->elf_filename)
		return false;
	abfd = bfd_openr(ss->elf_filename, NULL);
	if (!abfd || !bfd_check_format(abfd, bfd_object)) {
		if (abfd)
			bfd_close(abfd);
		return false;
	}
	for (section = abfd->sections; section; section = section->next) {
		bfd_vma start = bfd_section_vma(section);
		bfd_size_type size = bfd_section_size(section);
		struct image_section *image;

		if (!size)
			continue;
		image = image_section_find(ss, start);
		if (!image || image->start != start
		    || image->end - image->start != size
		    || strcmp(image->name, bfd_section_name(section)))
			continue;
		image->data = safe_malloc(size);
		if (!bfd_get_section_contents(abfd, section, image->data, 0, size)) {
			goto fail;
		}
		loaded++;
	}
	bfd_close(abfd);
	if (loaded != ss->nr_sections)
		goto clear;
	ss->image_data_loaded = true;
	return true;

fail:
	bfd_close(abfd);
clear:
	for (loaded = 0; loaded < ss->nr_sections; loaded++) {
		free(ss->sections[loaded].data);
		ss->sections[loaded].data = NULL;
	}
	return false;
}

bool sym_code_matches(void **store, uint64_t addr,
		      const uint8_t *code, size_t len)
{
	struct sym_store *ss = *store;
	struct image_section *section;

	if (!ss || !code || !len || addr > UINT64_MAX - len)
		return false;
	section = image_section_find(ss, addr);
	if (!section || addr + len > section->end || !load_image_data(ss))
		return false;
	return !memcmp(section->data + addr - section->start, code, len);
}

size_t sym_find_code_matches(void **store, const uint8_t *code, size_t len,
			     uint64_t *matches, size_t capacity)
{
	struct sym_store *ss = *store;
	size_t count = 0;
	size_t i;

	if (!ss || !code || !len || !load_image_data(ss))
		return 0;
	for (i = 0; i < ss->nr_sections; i++) {
		struct image_section *section = &ss->sections[i];
		size_t section_size = section->end - section->start;
		size_t offset;

		if (len > section_size)
			continue;
		for (offset = 0; offset <= section_size - len; offset++) {
			if (memcmp(section->data + offset, code, len))
				continue;
			if (count < capacity)
				matches[count] = section->start + offset;
			count++;
		}
	}
	return count;
}

uint64_t sym_image_coverage_at(void **store, uint64_t addr)
{
	struct sym_store *ss = *store;
	struct image_section *section;

	if (!ss)
		return 0;
	section = image_section_find(ss, addr);
	if (!section || !section->cov)
		return 0;
	return section->cov->counter[addr - section->start];
}

void sym_update_image_cov(void **store, uint64_t start, uint64_t end,
			  uint64_t count)
{
	struct sym_store *ss = *store;
	uint64_t cursor = start;

	if (!ss || end <= start)
		return;
	while (cursor < end) {
		struct image_section *section = image_section_find(ss, cursor);
		uint64_t section_end;
		uint64_t i;

		if (!section) {
			uint64_t next = next_image_section_start(ss, cursor);

			if (next == UINT64_MAX || next >= end)
				break;
			cursor = next;
			continue;
		}
		if (!section->cov) {
			uint64_t size = section->end - section->start;

			if (size > SIZE_MAX / sizeof(section->cov->counter[0])) {
				fprintf(stderr, "Executable ELF section is too large\n");
				exit(EXIT_FAILURE);
			}
			section->cov = safe_mallocz(
				size * sizeof(section->cov->counter[0]));
		}
		section_end = end < section->end ? end : section->end;
		for (i = cursor; i < section_end; i++)
			section->cov->counter[i - section->start] += count;
		cursor = section_end;
	}
}

void sym_update_cov(struct sym *sym, uint64_t start, uint64_t end,
			uint64_t time, uint64_t count)
{
	int64_t start_offset = start - sym->addr;
	int64_t len = end - start;
	uint64_t i, pos;
	uint64_t time_per_entry;
	uint64_t entries;
	uint64_t accounted = 0;

	/* Is this the unknown sym ?? */
	if (sym->namelen == 0)
		return;

	assert(start_offset >= 0);
	assert(start_offset + len <= sym->size);

	sym->total_time += time;

	if (!sym->cov)
		sym_alloc_cov(sym);

	entries = len;
	if (entries == 0)
		return;

	time_per_entry = time / entries;
	if (time_per_entry == 0 && time != 0)
		time_per_entry = 1;

	pos = start_offset;

	/* First update the nr entries.  */
	i = 0;
	do {
		sym->cov_ent->counter[pos + i] += count;
		i++;
	} while (i < entries);

repass:
	i = 0;
	do {
		sym->cov->counter[pos + i] += time_per_entry;
		accounted += time_per_entry;
		if (accounted >= time) {
			break;
		}
		i++;
	} while (i < entries);

	/* FIXME: spread the granularity error evenly.  */
	if (accounted < time) {
		time_per_entry = 1;
		goto repass;
	}

#if 0
	if (accounted != time)
		printf("WRONG COVERAGE accounted=%lu time=%lu tpe=%u entries=%lu\n",
			accounted, time, time_per_entry, entries);
#endif
	assert (accounted == time);
}

void sym_build_linemap(void **store, const char *dwarfdump, const char *elf)
{
	char *od_argv[] = { (char *) dwarfdump, "-l", (char *) elf, NULL };
	char tmpout_template[] = "/tmp/etrace-dd-out-XXXXXX";
	struct {
		uint64_t address;
		struct sym_src_loc *locs;
		bool valid;
	} pending = { 0 };
	unsigned int num_lines = 0;
	int stdio[3] = {0, 1, 2};
	int fdout_tmp;
	struct sym_store *ss = *store;
	char *filename = NULL;
	int pipefd[2];
	FILE *fp;
	int r;
	pid_t wpid;
	pid_t kid;

	fprintf(stderr, "Building linemap\n");

	r = pipe(pipefd);
	if (r < 0) {
		perror("mkstemp");
		exit(1);
	}
	fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

	fdout_tmp = mkstemp(tmpout_template);
	if (fdout_tmp < 0) {
		perror("mkstemp");
		exit(1);
	}
	unlink(tmpout_template);

	stdio[0] = pipefd[0];
	stdio[1] = fdout_tmp;
	kid = run(od_argv[0], od_argv, stdio);

	close(pipefd[0]);
	close(pipefd[1]);

	wpid = waitpid(kid, NULL, 0);
	if (wpid != kid) {
		perror("wait");
		exit(1);
	}

	lseek(fdout_tmp, 0, SEEK_SET);
	fp = fdopen(fdout_tmp, "r");
	if (!fp) {
		fprintf(stderr, "No linemap\n");
		exit(1);
	}
	while (!feof(fp)) {
		char line[512];
		struct dwarf_line_row row;
		char *s;

		s = fgets(line, sizeof line, fp);
		if (s == NULL) {
			break;
		}
		if (!strncmp(s, ".debug_line:", strlen(".debug_line:"))) {
			free_source_locs(pending.locs);
			pending.locs = NULL;
			pending.valid = false;
			free(filename);
			filename = NULL;
			continue;
		}
		if (!dwarf_line_parse(s, &row))
			continue;
		if (row.filename) {
			free(filename);
			filename = filename_sanitize(row.filename);
			free(row.filename);
			row.filename = NULL;
		}
		if (row.end_sequence) {
			if (pending.valid && row.address >= pending.address)
				add_line_range(ss, pending.address, row.address,
					       pending.locs);
			else
				free_source_locs(pending.locs);
			pending.locs = NULL;
			pending.valid = false;
			dwarf_line_row_clear(&row);
			continue;
		}
		if (!filename) {
			dwarf_line_row_clear(&row);
			continue;
		}

		if (pending.valid && row.address != pending.address) {
			if (row.address > pending.address)
				add_line_range(ss, pending.address, row.address,
					       pending.locs);
			else {
				fprintf(stderr,
					"Ignoring decreasing DWARF line address "
					"0x%" PRIx64 " after 0x%" PRIx64 "\n",
					row.address, pending.address);
				free_source_locs(pending.locs);
			}
			pending.locs = NULL;
			pending.valid = false;
		}
		if (!pending.valid) {
			pending.address = row.address;
			pending.valid = true;
		}
		append_source_loc(&pending.locs,
			new_source_loc(filename, row.line, row.discriminator,
				       0));
		num_lines++;
		dwarf_line_row_clear(&row);
	}

	free_source_locs(pending.locs);
	free(filename);
	fclose(fp);
	materialize_line_ranges(ss);
	if (!num_lines) {
		fprintf(stderr, "WARNING: Unable to create linemap\n");
	}
	fprintf(stderr, "done.\n");
}

static void sym_update_source_hits(struct sym_store *ss, const char *name,
				   const char *filename, uint64_t hits)
{
	size_t name_len = strlen(name);
	unsigned int i;

	if (!hits || !strcmp(name, "??") || !strcmp(filename, "??"))
		return;
	if (name_len > sizeof(ss->allsyms[0].name) - 2)
		name_len = sizeof(ss->allsyms[0].name) - 2;

	for (i = 0; i < ss->nr_stored; i++) {
		struct sym *sym = &ss->allsyms[i];

		if (sym->namelen != name_len
		    || strncmp(sym->name, name, name_len)
		    || !sym->src_filename
		    || strcmp(sym->src_filename, filename))
			continue;
		if (hits > sym->source_hits)
			sym->source_hits = hits;
	}
}

static bool parse_dwarf_address(const char *line, const char *attribute,
				uint64_t *addr)
{
	const char *value;
	char *end;

	if (!strstr(line, attribute))
		return false;
	value = strstr(line, "0x");
	if (!value)
		return false;
	errno = 0;
	*addr = strtoull(value, &end, 16);
	return !errno && end != value;
}

static void write_covered_address(struct sym_store *ss, int fd, uint64_t addr)
{
	void *store = ss;
	char text[32];
	int len;

	if (!sym_image_coverage_at(&store, addr))
		return;
	len = snprintf(text, sizeof(text), "0x%" PRIx64 "\n", addr);
	if (safe_write(fd, text, len) != len) {
		perror("addr2line input");
		exit(EXIT_FAILURE);
	}
}

static void write_inline_entries(struct sym_store *ss, int fd,
				 const char *dwarfdump, const char *elf)
{
	char *argv[] = { (char *)dwarfdump, "-i", (char *)elf, NULL };
	char tmpout_template[] = "/tmp/etrace-dd-info-XXXXXX";
	int stdio[3] = { 0, 1, 2 };
	uint64_t low_pc = 0;
	bool have_low_pc = false;
	bool have_entry_pc = false;
	bool in_inline = false;
	int fdout;
	int status;
	FILE *fp;
	pid_t kid;

	fdout = mkstemp(tmpout_template);
	if (fdout < 0) {
		perror("mkstemp");
		exit(EXIT_FAILURE);
	}
	unlink(tmpout_template);
	stdio[1] = fdout;
	kid = run(argv[0], argv, stdio);
	if (waitpid(kid, &status, 0) != kid || !WIFEXITED(status)
	    || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "dwarfdump failed\n");
		exit(EXIT_FAILURE);
	}

	lseek(fdout, 0, SEEK_SET);
	fp = fdopen(fdout, "r");
	if (!fp) {
		fprintf(stderr, "Unable to read dwarfdump output\n");
		exit(EXIT_FAILURE);
	}

	while (1) {
		char *line = NULL;
		size_t size = 0;
		ssize_t len = getline(&line, &size, fp);

		if (len < 0) {
			free(line);
			break;
		}
		if (strstr(line, "DW_TAG_")) {
			if (in_inline && have_low_pc && !have_entry_pc)
				write_covered_address(ss, fd, low_pc);
			in_inline = strstr(line, "DW_TAG_inlined_subroutine") != NULL;
			have_low_pc = false;
			have_entry_pc = false;
		} else if (in_inline
			   && parse_dwarf_address(line, "DW_AT_entry_pc", &low_pc)) {
			write_covered_address(ss, fd, low_pc);
			have_entry_pc = true;
		} else if (in_inline && !have_entry_pc
			   && parse_dwarf_address(line, "DW_AT_low_pc", &low_pc)) {
			have_low_pc = true;
		}
		free(line);
	}
	if (in_inline && have_low_pc && !have_entry_pc)
		write_covered_address(ss, fd, low_pc);
	fclose(fp);
}

void sym_build_source_coverage(void **store, const char *addr2line,
			       const char *dwarfdump, const char *elf)
{
	char *argv[] = { (char *)addr2line, "-a", "-f", "-i", "-C", "-p",
			 "-e", (char *)elf, NULL };
	char tmpin_template[] = "/tmp/etrace-a2l-in-XXXXXX";
	char tmpout_template[] = "/tmp/etrace-a2l-out-XXXXXX";
	struct sym_store *ss = *store;
	int stdio[3] = { 0, 1, 2 };
	uint64_t current_hits = 0;
	int fdin_tmp;
	int fdout_tmp;
	FILE *fp;
	pid_t kid;
	int status;
	unsigned int i;

	fprintf(stderr, "Building source function coverage\n");
	fdin_tmp = mkstemp(tmpin_template);
	if (fdin_tmp < 0) {
		perror("mkstemp");
		exit(EXIT_FAILURE);
	}
	unlink(tmpin_template);

	for (i = 0; i < ss->nr_stored; i++) {
		struct sym *sym = &ss->allsyms[i];

		sym->source_hits = sym_image_coverage_at(store, sym->addr);
	}
	write_inline_entries(ss, fdin_tmp, dwarfdump, elf);
	lseek(fdin_tmp, 0, SEEK_SET);

	fdout_tmp = mkstemp(tmpout_template);
	if (fdout_tmp < 0) {
		perror("mkstemp");
		exit(EXIT_FAILURE);
	}
	unlink(tmpout_template);

	stdio[0] = fdin_tmp;
	stdio[1] = fdout_tmp;
	kid = run(argv[0], argv, stdio);
	if (waitpid(kid, &status, 0) != kid || !WIFEXITED(status)
	    || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "addr2line failed\n");
		exit(EXIT_FAILURE);
	}
	close(fdin_tmp);

	lseek(fdout_tmp, 0, SEEK_SET);
	fp = fdopen(fdout_tmp, "r");
	if (!fp) {
		fprintf(stderr, "Unable to read addr2line output\n");
		exit(EXIT_FAILURE);
	}

	while (1) {
		char *line = NULL;
		char *function;
		char *location;
		char *separator;
		char *colon;
		char *sanitized;
		size_t size = 0;
		ssize_t len;

		len = getline(&line, &size, fp);
		if (len < 0) {
			free(line);
			break;
		}
		if (!strncmp(line, "0x", 2)) {
			void *store = ss;
			char *end;
			uint64_t addr = strtoull(line, &end, 16);

			current_hits = sym_image_coverage_at(&store, addr);
			if (end[0] != ':' || end[1] != ' ') {
				free(line);
				continue;
			}
			function = end + 2;
		} else if (!strncmp(line, " (inlined by) ", 14)) {
			function = line + 14;
		} else {
			free(line);
			continue;
		}

		separator = strstr(function, " at ");
		if (!separator) {
			free(line);
			continue;
		}
		*separator = '\0';
		location = separator + 4;
		colon = strrchr(location, ':');
		if (!colon) {
			free(line);
			continue;
		}
		*colon = '\0';
		sanitized = filename_sanitize(location);
		sym_update_source_hits(ss, function, sanitized, current_hits);
		free(sanitized);
		free(line);
	}

	fclose(fp);
	fprintf(stderr, "done.\n");
}


static void process_nm_output(void **store, char *s, size_t len)
{
	struct sym_store *ss;
	char *end = s + len;
	int i;

	ss = safe_mallocz(sizeof *ss);
	*store = ss;
	ss->min = ~(0ULL);

	fprintf(stderr, "Build symtab\n");
	while (s < end) {
		struct sym parsed = { 0 };
		char *line_end = memchr(s, '\n', end - s);
		char *name;
		char *next;
		char *p = s;
		bool have_size = false;
		int type;
		size_t name_len;

		if (!line_end)
			line_end = end;
		while (p < line_end && isspace((unsigned char)*p))
			p++;
		errno = 0;
		parsed.addr = strtoull(p, &next, 16);
		if (next == p) {
			s = line_end < end ? line_end + 1 : end;
			continue;
		}
		if (parsed.addr == ULLONG_MAX && errno == ERANGE)
			goto fail;
		p = next;
		while (p < line_end && isspace((unsigned char)*p))
			p++;

		errno = 0;
		parsed.size = strtoull(p, &next, 16);
		if (next != p) {
			if (parsed.size == ULLONG_MAX && errno == ERANGE)
				goto fail;
			have_size = true;
			p = next;
		}
		while (p < line_end && isspace((unsigned char)*p))
			p++;
		if (p == line_end)
			goto fail;
		type = *p++;
		while (p < line_end && isspace((unsigned char)*p))
			p++;
		name = p;
		name_len = line_end - name;
		if (name_len && name[name_len - 1] == '\r')
			name_len--;
		s = line_end < end ? line_end + 1 : end;

		if (type != 'T' && type != 't'
		    && type != 'W' && type != 'w')
			continue;

		if (!name_len)
			goto fail;
		if (name_len > sizeof(parsed.name) - 1)
			name_len = sizeof(parsed.name) - 1;
		memcpy(parsed.name, name, name_len);
		parsed.name[name_len] = '\0';
		parsed.namelen = name_len;
		if (have_size)
			parsed.flags |= SYM_F_EXPLICIT_SIZE;
		if (type == 't' || type == 'w')
			parsed.flags |= SYM_F_LOCAL;
		else
			parsed.flags |= SYM_F_GLOBAL;
		if (type == 'W' || type == 'w')
			parsed.flags |= SYM_F_WEAK;

		ss->allsyms = safe_realloc(ss->allsyms,
			(sizeof(parsed) * (ss->nr_stored + 1)));
		ss->allsyms[ss->nr_stored] = parsed;
		ss->nr_stored++;
		if (parsed.addr < ss->min)
			ss->min = parsed.addr;
		if (parsed.size <= UINT64_MAX - parsed.addr
		    && parsed.addr + parsed.size > ss->max)
			ss->max = parsed.addr + parsed.size;
	}

	qsort(ss->allsyms, ss->nr_stored, sizeof(ss->allsyms[0]), sym_compare);

	/* Now we are done.  */
	for (i = 0; i < ss->nr_stored; i++) {
		tsearch(&ss->allsyms[i], &ss->rootp, sym_str_compare);
	}

	/* Init the unknown.  */
	ss->unknown.size = ~0;
	fprintf(stderr, "done.\n");
	return;
fail:
	fprintf(stderr, "Invalid nm output\n");
	exit(1);
}

/*
 * Build a symtab.
 * TODO: Use binutils libs or libreadelf.
 */
void sym_read_from_elf(void **rootp, char *nm, char *elf)
{
	char *nm_argv[] = { nm, "-C", "-S", elf, NULL };
	char *output;
	char tmp_template[] = "/tmp/etrace-nm-XXXXXX";
	long pagesize = sysconf(_SC_PAGE_SIZE);
	int stdio[3] = {0, 1, 2};
	int fd_tmp;
	size_t fsize, fsize_aligned;
	pid_t wpid;
	pid_t kid;

	fd_tmp = mkstemp(tmp_template);
	if (fd_tmp < 0) {
		perror("mkstemp");
		exit(1);
	}
	unlink(tmp_template);

	stdio[1] = fd_tmp;
	kid = run(nm_argv[0], nm_argv, stdio);
	wpid = waitpid(kid, NULL, 0);
	if (wpid != kid) {
		perror("wait");
		exit(1);
	}

	/* Done, now mmap the file.  */
	fsize = get_filesize(fd_tmp);
	fsize_aligned = align_pow2(fsize, pagesize);
	output = mmap(NULL, fsize_aligned, PROT_READ, MAP_PRIVATE, fd_tmp, 0);
	if (output == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	process_nm_output(rootp, output, fsize);
	read_executable_sections(*rootp, elf);
	close(fd_tmp);
}
