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
#include <glib.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

#include <search.h>

#include "config.h"
#include "filename.h"
#include "dwarf-decl.h"
#include "dwarf-lines.h"
#include "util.h"
#include "safeio.h"
#include "syms.h"
#include "run.h"
#include "inline-entry.h"

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
	struct sym_load_segment *load_segments;
	size_t nr_load_segments;
	struct x86_alt_replacement {
		uint64_t addr;
		uint8_t len;
	} *x86_alt_replacements;
	size_t nr_x86_alt_replacements;
	struct x86_alt_patch {
		uint64_t addr;
		uint16_t len;
		uint8_t original_len;
		uint8_t padding_len;
		bool empty_replacement;
		size_t first_replacement;
		size_t nr_replacements;
	} *x86_alt_patches;
	size_t nr_x86_alt_patches;
	uint64_t *alt_call_sites;
	size_t nr_alt_call_sites;
	uint16_t elf_machine;
	bool elf_big_endian;
	bool x86_64;
	bool xen_alt_metadata;
};

static struct sym *find_bfd_symbol(struct sym_store *ss, const char *name,
				   uint64_t addr);

static uint16_t elf16(const uint8_t *data, bool big_endian)
{
	return big_endian ? ((uint16_t)data[0] << 8) | data[1]
		: data[0] | ((uint16_t)data[1] << 8);
}

static uint32_t elf32(const uint8_t *data, bool big_endian)
{
	uint32_t value = 0;
	unsigned int i;

	for (i = 0; i < 4; i++) {
		unsigned int byte = big_endian ? i : 3 - i;

		value = (value << 8) | data[byte];
	}
	return value;
}

static uint64_t elf64(const uint8_t *data, bool big_endian)
{
	uint64_t value = 0;
	unsigned int i;

	for (i = 0; i < 8; i++) {
		unsigned int byte = big_endian ? i : 7 - i;

		value = (value << 8) | data[byte];
	}
	return value;
}

static void read_executable_load_segments(struct sym_store *ss,
					  const char *filename)
{
	uint8_t header[sizeof(Elf64_Ehdr)];
	uint8_t program[sizeof(Elf64_Phdr)];
	uint64_t program_offset;
	uint16_t program_size;
	uint16_t program_count;
	bool big_endian;
	bool elf64_format;
	FILE *fp;
	uint16_t i;

	fp = fopen(filename, "rb");
	if (!fp || fread(header, 1, sizeof(header), fp) != sizeof(header)
	    || memcmp(header, ELFMAG, SELFMAG)
	    || (header[EI_CLASS] != ELFCLASS32
		&& header[EI_CLASS] != ELFCLASS64)
	    || (header[EI_DATA] != ELFDATA2LSB
		&& header[EI_DATA] != ELFDATA2MSB)) {
		fprintf(stderr, "Unable to read ELF program headers from %s\n",
			filename);
		if (fp)
			fclose(fp);
		exit(EXIT_FAILURE);
	}
	big_endian = header[EI_DATA] == ELFDATA2MSB;
	ss->elf_big_endian = big_endian;
	elf64_format = header[EI_CLASS] == ELFCLASS64;
	ss->elf_machine = elf16(header + 18, big_endian);
	if (elf64_format) {
		program_offset = elf64(header + 32, big_endian);
		program_size = elf16(header + 54, big_endian);
		program_count = elf16(header + 56, big_endian);
	} else {
		program_offset = elf32(header + 28, big_endian);
		program_size = elf16(header + 42, big_endian);
		program_count = elf16(header + 44, big_endian);
	}
	if (program_count == PN_XNUM
	    || (program_count
		&& program_size != (elf64_format ? sizeof(Elf64_Phdr)
					     : sizeof(Elf32_Phdr)))) {
		fprintf(stderr, "Unsupported ELF program header table in %s\n",
			filename);
		fclose(fp);
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < program_count; i++) {
		uint64_t offset;
		uint64_t linked;
		uint64_t image;
		uint64_t file_size;
		uint64_t memory_size;
		uint32_t type;
		uint32_t flags;

		if (i > (UINT64_MAX - program_offset) / program_size
		    || program_offset + (uint64_t)i * program_size > INT64_MAX
		    || fseeko(fp, program_offset + (uint64_t)i * program_size,
			      SEEK_SET) != 0
		    || fread(program, 1, program_size, fp) != program_size) {
			fprintf(stderr, "Unable to read ELF program headers from %s\n",
				filename);
			fclose(fp);
			exit(EXIT_FAILURE);
		}
		type = elf32(program, big_endian);
		if (elf64_format) {
			flags = elf32(program + 4, big_endian);
			offset = elf64(program + 8, big_endian);
			linked = elf64(program + 16, big_endian);
			image = elf64(program + 24, big_endian);
			file_size = elf64(program + 32, big_endian);
			memory_size = elf64(program + 40, big_endian);
		} else {
			offset = elf32(program + 4, big_endian);
			linked = elf32(program + 8, big_endian);
			image = elf32(program + 12, big_endian);
			file_size = elf32(program + 16, big_endian);
			memory_size = elf32(program + 20, big_endian);
			flags = elf32(program + 24, big_endian);
		}
		(void)offset;
		if (type != PT_LOAD || !(flags & PF_X) || !memory_size)
			continue;
		if (linked > UINT64_MAX - memory_size
		    || image > UINT64_MAX - memory_size
		    || file_size > memory_size) {
			fprintf(stderr, "Invalid executable ELF load segment in %s\n",
				filename);
			fclose(fp);
			exit(EXIT_FAILURE);
		}
		ss->load_segments = safe_realloc(ss->load_segments,
			(sizeof(*ss->load_segments) * (ss->nr_load_segments + 1)));
		ss->load_segments[ss->nr_load_segments++] =
			(struct sym_load_segment) {
				.linked_start = linked,
				.image_start = image,
				.file_size = file_size,
				.memory_size = memory_size,
			};
	}
	fclose(fp);
}

const struct sym_load_segment *sym_get_executable_load_segments(
	void **store, size_t *nr_segments)
{
	struct sym_store *ss = *store;

	if (!ss) {
		*nr_segments = 0;
		return NULL;
	}
	*nr_segments = ss->nr_load_segments;
	return ss->load_segments;
}

uint16_t sym_get_elf_machine(void **store)
{
	struct sym_store *ss = *store;

	return ss ? ss->elf_machine : EM_NONE;
}

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

static void set_function_declaration(struct sym_store *ss,
				     const struct dwarf_decl *declaration)
{
	struct sym *sym = find_bfd_symbol(ss, declaration->name,
					  declaration->address);
	char *filename;

	if (!sym || !(sym->flags & SYM_F_FUNCTION)
	    || !(sym->flags & SYM_F_EXECUTABLE) || sym->declaration_ambiguous)
		return;
	filename = filename_sanitize(declaration->filename);
	if (sym->declaration.filename) {
		if (sym->declaration.linenr == declaration->line
		    && !strcmp(sym->declaration.filename, filename)) {
			free(filename);
			return;
		}
		free((void *)sym->declaration.filename);
		memset(&sym->declaration, 0, sizeof(sym->declaration));
		sym->declaration_ambiguous = true;
		free(filename);
		return;
	}
	sym->declaration.filename = filename;
	sym->declaration.linenr = declaration->line;
}

static void read_function_declarations(struct sym_store *ss,
				       const char *dwarfdump, const char *elf)
{
	char *argv[] = { (char *)dwarfdump, "-i", "-G", (char *)elf, NULL };
	struct dwarf_declarations declarations;
	int stdio[3] = { STDIN_FILENO, -1, STDERR_FILENO };
	FILE *output = tmpfile();
	pid_t child;
	int status;
	size_t i;

	if (!output) {
		perror("tmpfile");
		exit(EXIT_FAILURE);
	}
	stdio[1] = fileno(output);
	child = run(argv[0], argv, stdio);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
	    || WEXITSTATUS(status) != 0 || fseek(output, 0, SEEK_SET) != 0) {
		fprintf(stderr, "dwarfdump failed\n");
		exit(EXIT_FAILURE);
	}
	if (!dwarf_declarations_parse(output, &declarations)) {
		fprintf(stderr, "Unable to parse DWARF function declarations\n");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < declarations.count; i++)
		set_function_declaration(ss, &declarations.entries[i]);
	dwarf_declarations_destroy(&declarations);
	fclose(output);
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

static int uint64_compare(const void *a, const void *b)
{
	uint64_t av = *(const uint64_t *)a;
	uint64_t bv = *(const uint64_t *)b;

	return av < bv ? -1 : av > bv;
}

static bool add_relative_s32(uint64_t base, int32_t delta, uint64_t *result)
{
	if (delta >= 0) {
		if (base > UINT64_MAX - (uint32_t)delta)
			return false;
		*result = base + (uint32_t)delta;
	} else {
		uint64_t magnitude = -(int64_t)delta;

		if (base < magnitude)
			return false;
		*result = base - magnitude;
	}
	return true;
}

static void invalid_alt_call_metadata(void)
{
	fprintf(stderr, "Invalid ELF alternative-call metadata\n");
	exit(EXIT_FAILURE);
}

static void invalid_alt_instruction_metadata(void)
{
	fprintf(stderr, "Invalid ELF alternative-instruction metadata\n");
	exit(EXIT_FAILURE);
}

static void bfd_symbol_range(bfd *abfd,
			     const char *start_name, uint64_t *start,
			     const char *end_name, uint64_t *end,
			     bool *have_start, bool *have_end,
			     void (*invalid_metadata)(void))
{
	asymbol **symbols;
	long storage;
	long count;
	long i;

	*have_start = false;
	*have_end = false;

	storage = bfd_get_symtab_upper_bound(abfd);
	if (storage <= 0)
		return;
	symbols = safe_malloc(storage);
	count = bfd_canonicalize_symtab(abfd, symbols);
	if (count < 0) {
		free(symbols);
		invalid_metadata();
	}
	for (i = 0; i < count; i++) {
		asymbol *symbol = symbols[i];
		const char *name = bfd_asymbol_name(symbol);
		uint64_t value = bfd_asymbol_value(symbol);

		if (!strcmp(name, start_name)) {
			if (*have_start && *start != value) {
				free(symbols);
				invalid_metadata();
			}
			*start = value;
			*have_start = true;
		} else if (!strcmp(name, end_name)) {
			if (*have_end && *end != value) {
				free(symbols);
				invalid_metadata();
			}
			*end = value;
			*have_end = true;
		}
	}
	free(symbols);
}

static void read_alt_call_sites(struct sym_store *ss, bfd *abfd)
{
	asection *section;
	uint8_t *data;
	uint64_t start = 0;
	uint64_t end = 0;
	size_t count;
	size_t i;
	bool have_start;
	bool have_end;

	if (!ss->x86_64)
		return;
	bfd_symbol_range(abfd,
			 "__alt_call_sites_start", &start,
			 "__alt_call_sites_end", &end,
			 &have_start, &have_end, invalid_alt_call_metadata);
	if (!have_start && !have_end)
		return;
	if (!have_start || !have_end || end < start
	    || (end - start) % sizeof(uint32_t))
		invalid_alt_call_metadata();
	ss->xen_alt_metadata = true;
	if (end == start)
		return;
	if (end - start > SIZE_MAX)
		invalid_alt_call_metadata();
	for (section = abfd->sections; section; section = section->next) {
		uint64_t section_start = bfd_section_vma(section);
		uint64_t section_size = bfd_section_size(section);

		if (section_start <= start
		    && section_size <= UINT64_MAX - section_start
		    && end <= section_start + section_size)
			break;
	}
	if (!section)
		invalid_alt_call_metadata();
	count = (end - start) / sizeof(uint32_t);
	data = safe_malloc(end - start);
	if (!bfd_get_section_contents(abfd, section, data,
				      start - bfd_section_vma(section), end - start)) {
		free(data);
		invalid_alt_call_metadata();
	}
	ss->alt_call_sites = safe_malloc(count * sizeof(*ss->alt_call_sites));
	for (i = 0; i < count; i++) {
		uint64_t entry = start + i * sizeof(uint32_t);
		uint32_t raw = elf32(data + i * sizeof(uint32_t),
				     ss->elf_big_endian);
		int32_t delta;
		uint64_t call;
		asection *call_section;
		uint8_t opcode[2];
		void *image = ss;

		memcpy(&delta, &raw, sizeof(delta));
		if (!add_relative_s32(entry, delta, &call)
		    || call > UINT64_MAX - 6
		    || !sym_range_is_executable(&image, call, call + 6)) {
			free(data);
			invalid_alt_call_metadata();
		}
		for (call_section = abfd->sections; call_section;
		     call_section = call_section->next) {
			uint64_t section_start = bfd_section_vma(call_section);
			uint64_t section_size = bfd_section_size(call_section);

			if (section_start <= call
			    && section_size <= UINT64_MAX - section_start
			    && call + 6 <= section_start + section_size)
				break;
		}
		if (!call_section
		    || !bfd_get_section_contents(abfd, call_section, opcode,
						 call - bfd_section_vma(call_section),
						 sizeof(opcode))
		    || opcode[0] != 0xff || opcode[1] != 0x15) {
			free(data);
			invalid_alt_call_metadata();
		}
		ss->alt_call_sites[i] = call;
	}
	free(data);
	qsort(ss->alt_call_sites, count, sizeof(*ss->alt_call_sites),
	      uint64_compare);
	for (i = 1; i < count; i++) {
		if (ss->alt_call_sites[i] == ss->alt_call_sites[i - 1])
			invalid_alt_call_metadata();
	}
	ss->nr_alt_call_sites = count;
}

#define X86_ALT_RECORD_SIZE 14

struct x86_alt_record {
	uint64_t addr;
	uint64_t replacement;
	uint16_t len;
	uint8_t original_len;
	uint8_t replacement_len;
	uint8_t padding_len;
	bool empty_replacement;
};

static int x86_alt_record_compare(const void *a, const void *b)
{
	const struct x86_alt_record *ra = a;
	const struct x86_alt_record *rb = b;

	if (ra->addr < rb->addr)
		return -1;
	if (ra->addr > rb->addr)
		return 1;
	return ra->len < rb->len ? -1 : ra->len > rb->len;
}

static bool bfd_range_has_contents(bfd *abfd, uint64_t start, size_t len)
{
	asection *section;

	if (!len || start > UINT64_MAX - len)
		return false;
	for (section = abfd->sections; section; section = section->next) {
		uint64_t section_start = bfd_section_vma(section);
		uint64_t section_size = bfd_section_size(section);

		if ((bfd_section_flags(section) & SEC_HAS_CONTENTS)
		    && section_start <= start
		    && section_size <= UINT64_MAX - section_start
		    && start + len <= section_start + section_size)
			return true;
	}
	return false;
}

static void read_x86_alt_instructions(struct sym_store *ss, bfd *abfd)
{
	struct x86_alt_record *records;
	asection *section;
	uint8_t *data;
	uint64_t start = 0;
	uint64_t end = 0;
	size_t count;
	size_t i;
	bool have_start;
	bool have_end;
	void *image = ss;

	if (!ss->x86_64 || !ss->xen_alt_metadata)
		return;
	bfd_symbol_range(abfd,
			 "__alt_instructions", &start,
			 "__alt_instructions_end", &end,
			 &have_start, &have_end,
			 invalid_alt_instruction_metadata);
	if (!have_start && !have_end)
		return;
	if (!have_start || !have_end || end < start
	    || (end - start) % X86_ALT_RECORD_SIZE)
		invalid_alt_instruction_metadata();
	if (end == start)
		return;
	if (end - start > SIZE_MAX)
		invalid_alt_instruction_metadata();
	for (section = abfd->sections; section; section = section->next) {
		uint64_t section_start = bfd_section_vma(section);
		uint64_t section_size = bfd_section_size(section);

		if ((bfd_section_flags(section) & SEC_HAS_CONTENTS)
		    && section_start <= start
		    && section_size <= UINT64_MAX - section_start
		    && end <= section_start + section_size)
			break;
	}
	if (!section)
		invalid_alt_instruction_metadata();
	count = (end - start) / X86_ALT_RECORD_SIZE;
	if (count > SIZE_MAX / sizeof(*records))
		invalid_alt_instruction_metadata();
	data = safe_malloc(end - start);
	if (!bfd_get_section_contents(abfd, section, data,
				      start - bfd_section_vma(section), end - start)) {
		free(data);
		invalid_alt_instruction_metadata();
	}
	records = safe_malloc(count * sizeof(*records));
	for (i = 0; i < count; i++) {
		const uint8_t *record = data + i * X86_ALT_RECORD_SIZE;
		uint64_t entry = start + i * X86_ALT_RECORD_SIZE;
		uint32_t raw_origin = elf32(record, ss->elf_big_endian);
		uint32_t raw_replacement = elf32(record + 4,
						 ss->elf_big_endian);
		uint8_t original_len = record[10];
		uint8_t replacement_len = record[11];
		uint8_t padding_len = record[12];
		uint16_t total_len = (uint16_t)original_len + padding_len;
		int32_t origin_delta;
		int32_t replacement_delta;
		uint64_t origin;
		uint64_t replacement;

		memcpy(&origin_delta, &raw_origin, sizeof(origin_delta));
		memcpy(&replacement_delta, &raw_replacement,
		       sizeof(replacement_delta));
		if (!add_relative_s32(entry, origin_delta, &origin)
		    || !add_relative_s32(entry + 4, replacement_delta,
					 &replacement)
		    || !total_len || replacement_len > total_len
		    || origin > UINT64_MAX - total_len
		    || !sym_range_is_executable(&image, origin,
					origin + total_len)
		    || (replacement_len
			&& !bfd_range_has_contents(abfd, replacement,
						   replacement_len))
		    || record[13]) {
			free(records);
			free(data);
			invalid_alt_instruction_metadata();
		}
		records[i] = (struct x86_alt_record) {
			.addr = origin,
			.replacement = replacement,
			.len = total_len,
			.original_len = original_len,
			.replacement_len = replacement_len,
			.padding_len = padding_len,
			.empty_replacement = replacement_len == 0,
		};
	}
	free(data);
	qsort(records, count, sizeof(*records), x86_alt_record_compare);
	ss->x86_alt_patches = safe_malloc(count
					    * sizeof(*ss->x86_alt_patches));
	for (i = 0; i < count;) {
		size_t next = i + 1;
		size_t j;
		bool empty_replacement = records[i].empty_replacement;
		struct x86_alt_patch *patch;

		while (next < count && records[next].addr == records[i].addr) {
			if (records[next].len != records[i].len
			    || records[next].original_len
			       != records[i].original_len
			    || records[next].padding_len
			       != records[i].padding_len) {
				free(records);
				invalid_alt_instruction_metadata();
			}
			empty_replacement |= records[next].empty_replacement;
			next++;
		}
		if (next < count
		    && records[i].addr + records[i].len > records[next].addr) {
			free(records);
			invalid_alt_instruction_metadata();
		}
		patch = &ss->x86_alt_patches[ss->nr_x86_alt_patches++];
		patch->addr = records[i].addr;
		patch->len = records[i].len;
		patch->original_len = records[i].original_len;
		patch->padding_len = records[i].padding_len;
		patch->empty_replacement = empty_replacement;
		patch->first_replacement = ss->nr_x86_alt_replacements;
		patch->nr_replacements = 0;
		for (j = i; j < next; j++) {
			struct x86_alt_replacement *replacement;

			if (!records[j].replacement_len)
				continue;
			ss->x86_alt_replacements = safe_realloc(
				ss->x86_alt_replacements,
				(ss->nr_x86_alt_replacements + 1)
				* sizeof(*ss->x86_alt_replacements));
			replacement = &ss->x86_alt_replacements[
				ss->nr_x86_alt_replacements++];
			replacement->addr = records[j].replacement;
			replacement->len = records[j].replacement_len;
			patch->nr_replacements++;
		}
		i = next;
	}
	free(records);
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
	read_executable_load_segments(ss, elf);
	abfd = bfd_openr(elf, NULL);
	if (!abfd || !bfd_check_format(abfd, bfd_object)) {
		fprintf(stderr, "Unable to read ELF sections from %s: %s\n",
			elf, bfd_errmsg(bfd_get_error()));
		exit(EXIT_FAILURE);
	}
	{
		uint8_t header[20];
		FILE *fp = fopen(elf, "rb");

		ss->x86_64 = fp && fread(header, 1, sizeof(header), fp) == sizeof(header)
			&& !memcmp(header, "\177ELF", 4) && header[4] == 2
			&& ((header[5] == 1 && header[18] == 62 && header[19] == 0)
			    || (header[5] == 2 && header[18] == 0 && header[19] == 62));
		if (fp)
			fclose(fp);
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
	read_alt_call_sites(ss, abfd);
	read_x86_alt_instructions(ss, abfd);
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

static const uint8_t x86_k8_nops[] = {
	0x90,
	0x66, 0x90,
	0x66, 0x66, 0x90,
	0x66, 0x66, 0x66, 0x90,
	0x66, 0x66, 0x90, 0x66, 0x90,
	0x66, 0x66, 0x90, 0x66, 0x66, 0x90,
	0x66, 0x66, 0x66, 0x90, 0x66, 0x66, 0x90,
	0x66, 0x66, 0x66, 0x90, 0x66, 0x66, 0x66, 0x90,
	0x66, 0x66, 0x90, 0x66, 0x66, 0x90, 0x66, 0x66, 0x90,
};

static const uint8_t x86_p6_nops[] = {
	0x90,
	0x66, 0x90,
	0x0f, 0x1f, 0x00,
	0x0f, 0x1f, 0x40, 0x00,
	0x0f, 0x1f, 0x44, 0x00, 0x00,
	0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
	0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static bool x86_nops_match(const uint8_t *code, size_t len,
			   const uint8_t *nops)
{
	while (len) {
		size_t nop_len = MIN(len, 9);
		size_t offset = nop_len * (nop_len - 1) / 2;

		if (memcmp(code, nops + offset, nop_len))
			return false;
		code += nop_len;
		len -= nop_len;
	}
	return true;
}

static bool x86_nops_slice_match(const uint8_t *code, size_t offset,
				  size_t len, size_t total,
				  const uint8_t *nops)
{
	size_t end;
	size_t pos = 0;

	if (offset > total || len > total - offset)
		return false;
	end = offset + len;
	while (pos < total) {
		size_t nop_len = MIN(total - pos, 9);
		size_t nop_offset = nop_len * (nop_len - 1) / 2;
		size_t match_start = MAX(pos, offset);
		size_t match_end = MIN(pos + nop_len, end);

		if (match_start < match_end
		    && memcmp(code + match_start - offset,
			      nops + nop_offset + match_start - pos,
			      match_end - match_start))
			return false;
		pos += nop_len;
	}
	return true;
}

static bool x86_alt_replacement_matches(
	const struct x86_alt_patch *patch,
	const struct x86_alt_replacement *replacement,
	const uint8_t *replacement_bytes, const uint8_t *relocated_prefix,
	uint64_t addr,
	const uint8_t *code, size_t span, const uint8_t *nops)
{
	size_t offset = addr - patch->addr;
	size_t replacement_span;
	size_t relocated_span = 0;

	/* A padding-only fragment retains the existing partial-NOP policy. */
	if (offset >= replacement->len)
		return false;
	replacement_span = MIN(span, replacement->len - offset);
	if (relocated_prefix && offset < 5) {
		relocated_span = MIN(replacement_span, 5 - offset);
		if (memcmp(code, relocated_prefix + offset, relocated_span))
			return false;
	}
	if (memcmp(code + relocated_span,
		   replacement_bytes + offset + relocated_span,
		   replacement_span - relocated_span))
		return false;
	if (replacement_span == span)
		return true;
	return x86_nops_slice_match(code + replacement_span, 0,
		span - replacement_span, patch->len - replacement->len, nops);
}

static bool x86_alt_relocated_prefix(
	struct sym_store *ss, const struct x86_alt_patch *patch,
	const struct x86_alt_replacement *replacement,
	const uint8_t *bytes, uint8_t relocated[5])
{
	uint64_t replacement_next = replacement->addr + 5;
	uint64_t origin_next = patch->addr + 5;
	uint64_t target;
	uint64_t distance;
	uint32_t raw;
	int32_t displacement;
	void *store = ss;

	memcpy(&raw, bytes + 1, sizeof(raw));
	raw = GUINT32_FROM_LE(raw);
	memcpy(&displacement, &raw, sizeof(displacement));
	if (!add_relative_s32(replacement_next, displacement, &target)
	    || !sym_address_is_executable(&store, target))
		return false;
	if (target >= origin_next) {
		distance = target - origin_next;
		if (distance > INT32_MAX)
			return false;
		displacement = distance;
	} else {
		distance = origin_next - target;
		if (distance > (uint64_t)INT32_MAX + 1)
			return false;
		displacement = distance == (uint64_t)INT32_MAX + 1
			? INT32_MIN : -(int32_t)distance;
	}
	relocated[0] = bytes[0];
	memcpy(&raw, &displacement, sizeof(raw));
	raw = GUINT32_TO_LE(raw);
	memcpy(relocated + 1, &raw, sizeof(raw));
	return true;
}

static size_t x86_alt_replacement_span(struct sym_store *ss,
				       const struct x86_alt_patch *patch,
				       uint64_t addr, const uint8_t *code,
				       size_t len)
{
	size_t offset = addr - patch->addr;
	size_t span = MIN(len, patch->len - offset);
	size_t i;

	if (!span || !load_image_data(ss))
		return 0;
	for (i = 0; i < patch->nr_replacements; i++) {
		const struct x86_alt_replacement *replacement =
			&ss->x86_alt_replacements[patch->first_replacement + i];
		struct image_section *section;
		const uint8_t *bytes;
		const uint8_t *relocated_prefix = NULL;
		uint8_t relocated[5];
		bool initial_relative;

		section = image_section_find(ss, replacement->addr);
		if (!section
		    || replacement->addr + replacement->len > section->end)
			continue;
		bytes = section->data + replacement->addr - section->start;
		initial_relative = replacement->len >= 5
			&& (bytes[0] & 0xfe) == 0xe8;
		if (initial_relative) {
			if (!x86_alt_relocated_prefix(ss, patch, replacement,
						 bytes, relocated))
				continue;
			relocated_prefix = relocated;
		} else if (replacement->len > 5
			   && bytes[replacement->len - 5] == 0xe9) {
			/* Xen may relocate a trailing jump to __x86_return_thunk. */
			continue;
		}
		if (x86_alt_replacement_matches(patch, replacement, bytes,
			relocated_prefix, addr, code, span, x86_p6_nops)
		    || x86_alt_replacement_matches(patch, replacement, bytes,
			relocated_prefix, addr, code, span, x86_k8_nops))
			return span;
	}
	return 0;
}

size_t sym_x86_alt_patch_span(void **store, uint64_t addr,
			       const uint8_t *code, size_t len)
{
	struct sym_store *ss = *store;
	struct image_section *section;
	const uint8_t *original;
	size_t high;
	size_t low = 0;
	const struct x86_alt_patch *patch;

	if (!ss || !code)
		return 0;
	high = ss->nr_x86_alt_patches;
	while (low < high) {
		size_t mid = low + (high - low) / 2;

		if (ss->x86_alt_patches[mid].addr <= addr)
			low = mid + 1;
		else
			high = mid;
	}
	if (!low)
		return 0;
	patch = &ss->x86_alt_patches[low - 1];
	if (addr < patch->addr || addr - patch->addr >= patch->len)
		return 0;
	{
		size_t replacement_span = x86_alt_replacement_span(
			ss, patch, addr, code, len);

		if (replacement_span)
			return replacement_span;
	}
	if (patch->addr != addr || len < patch->len)
		return 0;
	if (patch->empty_replacement
	    && (x86_nops_match(code, patch->len, x86_p6_nops)
		|| x86_nops_match(code, patch->len, x86_k8_nops)))
		return patch->len;
	if (!load_image_data(ss))
		return 0;
	section = image_section_find(ss, patch->addr);
	if (!section || patch->addr + patch->len > section->end)
		return 0;
	original = section->data + patch->addr - section->start;
	if (memcmp(code, original, patch->original_len))
		return 0;
	code += patch->original_len;
	return (x86_nops_match(code, patch->padding_len, x86_p6_nops)
		|| x86_nops_match(code, patch->padding_len, x86_k8_nops))
		? patch->len : 0;
}

static bool find_alt_call_site(const struct sym_store *ss, uint64_t addr,
			       size_t len, uint64_t *site)
{
	size_t high = ss->nr_alt_call_sites;
	size_t low = 0;

	if (!len || addr > UINT64_MAX - len)
		return false;
	while (low < high) {
		size_t mid = low + (high - low) / 2;

		if (ss->alt_call_sites[mid] <= addr)
			low = mid + 1;
		else
			high = mid;
	}
	if (!low)
		return false;
	*site = ss->alt_call_sites[low - 1];
	return addr >= *site && addr + len <= *site + 6;
}

bool sym_instruction_matches(void **store, uint64_t addr,
			     const uint8_t *code, size_t len)
{
	static const uint8_t poison[6] = {
		0x0f, 0x0b, 0x0f, 0x0b, 0x0f, 0x0b,
	};
	struct sym_store *ss = *store;
	struct image_section *section;
	const uint8_t *original;
	uint64_t site;

	if (sym_code_matches(store, addr, code, len))
		return true;
	if (!ss || !ss->x86_64 || !code
	    || !find_alt_call_site(ss, addr, len, &site)
	    || !load_image_data(ss))
		return false;
	section = image_section_find(ss, site);
	if (!section || site + 6 > section->end)
		return false;
	original = section->data + site - section->start;
	if (original[0] != 0xff || original[1] != 0x15)
		return false;

	if (addr == site && len == 6 && code[0] == 0x2e && code[1] == 0xe8) {
		uint32_t raw;
		int32_t displacement;
		uint64_t target;

		memcpy(&raw, code + 2, sizeof(raw));
		raw = GUINT32_FROM_LE(raw);
		memcpy(&displacement, &raw, sizeof(displacement));
		return add_relative_s32(site + 6, displacement, &target)
			&& sym_address_is_executable(store, target);
	}
	return ((addr == site && len == sizeof(poison))
		|| (len == 2 && !((addr - site) & 1)))
		&& !memcmp(code, poison + addr - site, len);
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
			const uint8_t *candidate = memchr(section->data + offset,
				code[0], section_size - len - offset + 1);

			if (!candidate)
				break;
			offset = candidate - section->data;
			if (!memcmp(candidate, code, len)) {
				if (count < capacity)
					matches[count] = section->start + offset;
				count++;
			}
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
	read_function_declarations(ss, dwarfdump, elf);
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
		const char *source = sym->declaration.filename
			? sym->declaration.filename : sym->src_filename;

		if (sym->namelen != name_len
		    || strncmp(sym->name, name, name_len)
		    || !source || strcmp(source, filename))
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

static bool parse_objdump_target(const char *text, uint64_t *target)
{
	char *end;

	while (isspace((unsigned char)*text))
		text++;
	if (*text == '*')
		return false;
	errno = 0;
	*target = strtoull(text, &end, 16);
	return !errno && end != text;
}

static bool parse_objdump_instruction(struct sym_store *ss, const char *line,
				      struct inline_instruction *insn)
{
	const char *p = line;
	const char *mnemonic;
	char *end;
	uint8_t bytes[15];
	size_t count = 0;
	void *store = ss;

	while (isspace((unsigned char)*p))
		p++;
	errno = 0;
	insn->address = strtoull(p, &end, 16);
	if (errno || end == p || *end != ':')
		return false;
	p = end + 1;
	while (isspace((unsigned char)*p))
		p++;
	while (isxdigit((unsigned char)p[0])
	       && isxdigit((unsigned char)p[1])
	       && isspace((unsigned char)p[2])) {
		char byte[3] = { p[0], p[1], 0 };

		if (count == sizeof(bytes))
			return false;
		bytes[count++] = strtoul(byte, NULL, 16);
		p += 2;
		while (isspace((unsigned char)*p))
			p++;
	}
	if (!count || insn->address > UINT64_MAX - count
	    || !sym_code_matches(&store, insn->address, bytes, count))
		return false;
	insn->next = insn->address + count;
	insn->target = 0;
	insn->kind = INLINE_FLOW_NEXT;
	mnemonic = p;
	while (isalpha((unsigned char)*p) || *p == '.')
		p++;
	while (isspace((unsigned char)*p))
		p++;
	if (!strncmp(mnemonic, "jmp", 3)) {
		insn->kind = parse_objdump_target(p, &insn->target)
			? INLINE_FLOW_JUMP : INLINE_FLOW_STOP;
	} else if (mnemonic[0] == 'j' || !strncmp(mnemonic, "loop", 4)) {
		insn->kind = parse_objdump_target(p, &insn->target)
			? INLINE_FLOW_BRANCH : INLINE_FLOW_STOP;
	} else if (!strncmp(mnemonic, "ret", 3)
		   || !strncmp(mnemonic, "iret", 4)
		   || !strncmp(mnemonic, "sysret", 6)
		   || !strncmp(mnemonic, "syscall", 7)
		   || !strncmp(mnemonic, "sysenter", 8)
		   || !strncmp(mnemonic, "sysexit", 7)
		   || !strncmp(mnemonic, "hlt", 3)
		   || !strncmp(mnemonic, "int", 3)
		   || !strncmp(mnemonic, "ud", 2)
		   || !strncmp(mnemonic, "xabort", 6)
		   || !strncmp(mnemonic, "xbegin", 6)) {
		insn->kind = INLINE_FLOW_STOP;
	}
	return true;
}

static GArray *read_function_cfg(struct sym_store *ss, const char *objdump,
				 const char *elf, const struct sym *function)
{
	char start_arg[48], stop_arg[48];
	char *argv[] = { (char *)objdump, "-d", "--insn-width=16",
			 start_arg, stop_arg, (char *)elf, NULL };
	int stdio[3] = { STDIN_FILENO, -1, STDERR_FILENO };
	GArray *insns = NULL;
	FILE *output;
	int status;
	pid_t child;

	if (!function->size || function->size > 1024 * 1024
	    || function->addr > UINT64_MAX - function->size)
		return NULL;
	snprintf(start_arg, sizeof(start_arg), "--start-address=0x%" PRIx64,
		 function->addr);
	snprintf(stop_arg, sizeof(stop_arg), "--stop-address=0x%" PRIx64,
		 function->addr + function->size);
	output = tmpfile();
	if (!output)
		return NULL;
	stdio[1] = fileno(output);
	child = run(argv[0], argv, stdio);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
	    || WEXITSTATUS(status) != 0 || fseek(output, 0, SEEK_SET) != 0)
		goto out;
	insns = g_array_new(false, false, sizeof(struct inline_instruction));
	while (1) {
		char *line = NULL;
		size_t size = 0;
		struct inline_instruction insn;

		if (getline(&line, &size, output) < 0) {
			free(line);
			break;
		}
		if (parse_objdump_instruction(ss, line, &insn)) {
			if (insns->len
			    && g_array_index(insns, struct inline_instruction,
					     insns->len - 1).address >= insn.address) {
				free(line);
				g_array_free(insns, true);
				insns = NULL;
				goto out;
			}
			g_array_append_val(insns, insn);
		}
		free(line);
	}
	if (!insns->len
	    || g_array_index(insns, struct inline_instruction, 0).address
	       != function->addr) {
		g_array_free(insns, true);
		insns = NULL;
	}
out:
	fclose(output);
	return insns;
}

static bool parse_dwarf_range(const char *line, struct inline_range *range)
{
	const char *p;
	char *end;

	if (!strstr(line, "start,end") && !strstr(line, "range entry"))
		return false;
	p = strstr(line, "0x");
	if (!p)
		return false;
	errno = 0;
	range->start = strtoull(p, &end, 16);
	if (errno || end == p)
		return false;
	p = strstr(end, "0x");
	if (!p)
		return false;
	errno = 0;
	range->end = strtoull(p, &end, 16);
	return !errno && end != p && range->end > range->start;
}

static bool validate_inline_entry(struct sym_store *ss, const char *objdump,
				  const char *elf, uint64_t entry,
				  uint64_t candidate, const GArray *ranges)
{
	struct image_section *image = image_section_find(ss, entry);
	struct sym *function;
	GArray *cfg;
	void *store = ss;
	bool valid;

	if (!ss->x86_64 || !image || !load_image_data(ss)
	    || candidate < image->start || candidate >= image->end)
		return false;
	function = sym_lookup_by_addr(&store, entry);
	if (!function || candidate < function->addr
	    || candidate - function->addr >= function->size)
		return false;
	if (!inline_entry_clone_x86_64(image->data,
					image->end - image->start, image->start,
					entry, candidate,
					(const struct inline_range *)ranges->data,
					ranges->len))
	{
		return false;
	}
	cfg = read_function_cfg(ss, objdump, elf, function);
	if (!cfg)
		return false;
	valid = inline_entry_external_path(
		(const struct inline_instruction *)cfg->data, cfg->len, candidate,
		(const struct inline_range *)ranges->data, ranges->len);
	g_array_free(cfg, true);
	return valid;
}

static void write_inline_instance(struct sym_store *ss, int fd,
				  const char *objdump, const char *elf,
				  bool in_inline, bool have_entry_pc,
				  bool have_low_pc, uint64_t entry,
				  const GArray *ranges,
				  uint64_t *verified, uint64_t *unverified)
{
	unsigned int i;
	void *store = ss;

	if (!in_inline || (!have_entry_pc && !have_low_pc))
		return;
	write_covered_address(ss, fd, entry);
	if (sym_image_coverage_at(&store, entry))
		return;
	for (i = 0; i < ranges->len; i++) {
		const struct inline_range *range = &g_array_index(
			ranges, struct inline_range, i);

		if (range->start == entry
		    || !sym_image_coverage_at(&store, range->start))
			continue;
		if (validate_inline_entry(ss, objdump, elf, entry, range->start,
					  ranges)) {
			write_covered_address(ss, fd, range->start);
			(*verified)++;
		} else {
			(*unverified)++;
		}
	}
}

static void write_inline_entries(struct sym_store *ss, int fd,
				 const char *dwarfdump, const char *objdump,
				 const char *elf)
{
	char *argv[] = { (char *)dwarfdump, "-i", (char *)elf, NULL };
	char tmpout_template[] = "/tmp/etrace-dd-info-XXXXXX";
	int stdio[3] = { 0, 1, 2 };
	uint64_t low_pc = 0;
	bool have_low_pc = false;
	bool have_entry_pc = false;
	bool in_inline = false;
	GArray *ranges = g_array_new(false, false, sizeof(struct inline_range));
	uint64_t verified = 0, unverified = 0;
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
			write_inline_instance(ss, fd, objdump, elf, in_inline,
				have_entry_pc, have_low_pc, low_pc, ranges,
				&verified, &unverified);
			in_inline = strstr(line, "DW_TAG_inlined_subroutine") != NULL;
			have_low_pc = false;
			have_entry_pc = false;
			g_array_set_size(ranges, 0);
		} else if (in_inline
			   && parse_dwarf_address(line, "DW_AT_entry_pc", &low_pc)) {
			have_entry_pc = true;
		} else if (in_inline && !have_entry_pc
			   && parse_dwarf_address(line, "DW_AT_low_pc", &low_pc)) {
			have_low_pc = true;
		} else if (in_inline) {
			struct inline_range range;

			if (parse_dwarf_range(line, &range))
				g_array_append_val(ranges, range);
		}
		free(line);
	}
	write_inline_instance(ss, fd, objdump, elf, in_inline, have_entry_pc,
			      have_low_pc, low_pc, ranges, &verified, &unverified);
	if (verified || unverified)
		fprintf(stderr, "Inline alternate entries: verified=%" PRIu64
			" unverified=%" PRIu64 "\n", verified, unverified);
	g_array_free(ranges, true);
	fclose(fp);
}

void sym_build_source_coverage(void **store, const char *addr2line,
			       const char *dwarfdump, const char *objdump,
			       const char *elf)
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
	write_inline_entries(ss, fdin_tmp, dwarfdump, objdump, elf);
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
