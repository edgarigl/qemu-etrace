#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <search.h>

#include "util.h"
#include "safeio.h"
#include "syms.h"
#include "disas.h"
#include "run.h"

#include "coverage.h"
#include "cov-gcov.h"
#include "excludes.h"

#define MAX_RECORD_SIZE (32 * 1024)

#define D(x)

struct gcov_ctx {
	int fd;
	int fd_out;

	void **store;

	const char *gcov_strip;
	const char *gcov_prefix;

	struct gcov_file_header file_hdr;
	struct gcov_record_ir *rec;
};

struct gcov_file {
	struct gcov_file *next;
	const char *filename;
	int nr_syms;
	struct sym **syms;
	unsigned int nr_instrumented_lines;
	unsigned int nr_lines;
	int32_t *lines;
	bool *instr_lines;
};

struct gcov_file *gcov_files = NULL;

struct gcda_file {
	struct gcda_file *next;
	const char *name;
};
struct gcda_file *gcda_files = NULL;

struct gcda_file *gcda_find_file(const char *name)
{
	struct gcda_file *g = NULL, *tmp;

	tmp = gcda_files;
	while (tmp) {
		if (strcmp(name, tmp->name) == 0) {
			g = tmp;
			break;
		}
		tmp = tmp->next;
	}
	return g;
}

void gcda_add_file(const char *name)
{
	struct gcda_file *g;
	g = safe_mallocz(sizeof *g);
	g->name = strdup(name);
	g->next = gcda_files;
	gcda_files = g;
}

struct gcov_file *gcov_find_file(const char *name)
{
	struct gcov_file *f = gcov_files;

	while (f) {
		if (strcmp(name, f->filename) == 0)
			break;
		f = f->next;
	}
	return f;
}

struct gcov_file *gcov_find_file_no_fail(const char *name, unsigned int maxline)
{
	struct gcov_file *f;
	f = gcov_find_file(name);
	if (!f) {
		f = safe_mallocz(sizeof *f);
		f->lines = safe_mallocz(maxline * sizeof f->lines[0]);
		f->instr_lines = safe_mallocz(maxline * sizeof f->instr_lines[0]);
		f->nr_lines = maxline;
		f->filename = strdup(name);
		f->next = gcov_files;
		gcov_files = f;
	} else {
		if (maxline > f->nr_lines) {
			f->lines = safe_realloc(f->lines,
					maxline * sizeof f->lines[0]);
			f->instr_lines = safe_realloc(f->instr_lines,
					maxline * sizeof f->instr_lines[0]);
			memset(&f->lines[f->nr_lines], 0,
				(maxline - f->nr_lines) * sizeof f->lines[0]);
			memset(&f->instr_lines[f->nr_lines], 0,
				(maxline - f->nr_lines) * sizeof f->instr_lines[0]);
			f->nr_lines = maxline;
		}
	}
	return f;
}

void gcov_file_add_sym(struct gcov_file *f, struct sym *s)
{
	unsigned int i;

	for (i = 0; i < f->nr_syms; i++) {
		if (f->syms[i] == s)
			return;
	}

	f->nr_syms++;
	f->syms = safe_realloc(f->syms, sizeof f->syms[0] * f->nr_syms);
	f->syms[f->nr_syms - 1] = s;
}

char *gcov_map_srcfilename(const char *src, const char *gcov_strip,
			const char *gcov_prefix, bool remove_suffix,
			const char *new_suffix)
{
	char *f = (char *) src, *tmp = NULL, *n;
	size_t maxlen;
	unsigned int endpos;
	unsigned int strip_len = gcov_strip ? strlen(gcov_strip) : 0;
	unsigned int prefix_len = gcov_prefix ? strlen(gcov_prefix) : 0;

	assert(new_suffix);

	maxlen = prefix_len + strlen(src) + strlen(new_suffix) + 12;
	tmp = safe_malloc(maxlen);

	endpos = strlen(f);
	if (remove_suffix) {
		while (f[endpos] != '.' && endpos > 0)
			endpos--;

		/* No suffix?  */
		if (endpos == 0)
			goto fail;
	}
	/* IGnore.  */
	if (strip_len >= endpos)
		goto fail;

	if (strncmp(f, gcov_strip, strip_len) == 0) {
		f += strip_len;
	}

	n = tmp;
	if (prefix_len) {
		n = mempcpy(n, gcov_prefix, prefix_len);
	}
	n = mempcpy(n, f, endpos - strip_len);
	n = mempcpy(n, new_suffix, 6);
	return tmp;
fail:
	free(tmp);
	return NULL;
}


ssize_t gcov_read(int fd, void *buf, size_t count)
{
	ssize_t r;
	r = safe_read(fd, buf, count);
	if (r == -1) {
		perror("read");
		exit(1);
	}
	return r;
}

void gcov_write_string(int fd, const char *str)
{
	uint32_t len = strlen(str);
	safe_write(fd, &len, sizeof len);
	safe_write(fd, str, len);
}


bool gcov_read_file_header(int fd, struct gcov_file_header *h)
{
	ssize_t r;
	r = gcov_read(fd, h, sizeof *h);
	if (r < 0)
		return false;
	return true;
}

bool gcov_read_record(int fd, struct gcov_record *rec)
{
	ssize_t r;
	r = gcov_read(fd, &rec->hdr, sizeof rec->hdr);
	if (r < sizeof rec->hdr) {
		return false;
	}

	r = gcov_read(fd, &rec->data.u8[0], rec->hdr.length * 4);
	if (r < rec->hdr.length * 4) {
		return false;
	}
	return true;
}

bool gcov_parse_func_record(struct gcov_ctx *ctx)
{
	struct gcov_record *rec = &ctx->rec->rec;
	struct gcov_function *f = &ctx->rec->func;
	unsigned int pos = 0;
	unsigned int len;

	f->ident = rec->data.u32[pos++];
	f->csum = rec->data.u32[pos++];
	/* 4.7 format has an additional csum.  */
	/* 3430372a wants ++.
	   3430362a doesnt.  */
	if (ctx->file_hdr.version >= 0x3430372a) {
		f->cfg_csum = rec->data.u32[pos++];
	}

	len = rec->data.u32[pos++];
	f->name = strdup((char *) &rec->data.u32[pos]);
	pos += len;

	len = rec->data.u32[pos++];
	f->source = strdup((char *) &rec->data.u32[pos]);
	pos += len;

	f->lineno = rec->data.u32[pos++];

	D(printf("ident=%x csum=%x cfg_csum=%x\n",
		f->ident, f->csum, f->cfg_csum));
	D(printf("name=%s source=%s:%d\n", f->name, f->source, f->lineno));
	return true;
}

bool gcov_parse_block_record(struct gcov_ctx *ctx)
{
	struct gcov_record *rec = &ctx->rec->rec;
	struct gcov_blocks *b = &ctx->rec->blocks;
	unsigned int i;

	b->nr_blocks = rec->hdr.length;
	b->flags = safe_mallocz(sizeof *b->flags * b->nr_blocks);

	D(printf("nr_blocks=%d\n", b->nr_blocks));
	for (i = 0; i < b->nr_blocks; i++) {
		b->flags[i] = rec->data.u32[i];
		D(printf("flags=%x\n", b->flags[i]));
	}
	return true;
}

bool gcov_parse_arcs_record(struct gcov_arcs *b, struct gcov_record *rec)
{
	unsigned int pos = 0;

	b->block_no = rec->data.u32[pos++];
	D(printf("block_no=%x\n", b->block_no));

	b->nr_arcs = 0;
	while (pos < rec->hdr.length) {
		b->arcs[b->nr_arcs].dest_block = rec->data.u32[pos++];
		b->arcs[b->nr_arcs].flags = rec->data.u32[pos++];
		D(printf("arcs[%d] dest_block=%d flags=%x\n",
			b->nr_arcs, b->arcs[b->nr_arcs].dest_block,
			b->arcs[b->nr_arcs].flags));
		b->nr_arcs++;
		assert(b->nr_arcs < MAX_ARCS_PER_BLOCK);
	}
	return true;
}

bool gcov_parse_lines_record(struct gcov_lines *b, struct gcov_record *rec)
{
	unsigned int pos = 0;
	unsigned int len;
	char *name = NULL;

	b->nr_lines = 0;
	b->block_no = rec->data.u32[pos++];
	D(printf("blockno=%d\n", b->block_no));
	while (pos < rec->hdr.length) {
		uint32_t lineno;

		lineno = rec->data.u32[pos++];
		if (lineno == 0) {
			len = rec->data.u32[pos++];
			if (len == 0)
				break;
			name = (char *) &rec->data.u32[pos];
			pos += len;
			continue;
		}

//		assert(name != NULL);
		b->lines[b->nr_lines].lineno = lineno;
		b->lines[b->nr_lines].filename = name ? strdup(name) : NULL;
		D(printf("lines[%d] %s:%d\n",
			b->nr_lines, name, b->lines[b->nr_lines].lineno));
		b->nr_lines++;
		assert(b->nr_lines < MAX_LINES_PER_BLOCK);
	}
	return true;
}

bool gcov_parse_counts_record(struct gcov_counts *b, struct gcov_record *rec)
{
	unsigned int i;
	unsigned int pos = 0;

	b->nr_counts = rec->hdr.length / 2;
	b->counts = safe_mallocz(b->nr_counts * sizeof b->counts[0]);

	for (i = 0; i < b->nr_counts; i++) {
		b->counts[i] = rec->data.u64[pos++];
		D(printf("counts[%u] = %" PRIx64 "\n", i, b->counts[i]));
	}
	return true;
}

void gcov_parse_summary(struct gcov_summary *b, struct gcov_record *rec)
{
	unsigned int i;
	unsigned int pos = 0;

	b->checksum = rec->data.u32[pos++];

	for (i = 0; i < GCOV_COUNTERS_SUMMABLE; i++) {
		b->count_summary[i].num = rec->data.u32[pos++];
		b->count_summary[i].runs = rec->data.u32[pos++];
		b->count_summary[i].sum = rec->data.u32[pos++];
		b->count_summary[i].sum += (uint64_t) rec->data.u32[pos++] << 32;
		b->count_summary[i].max = rec->data.u32[pos++];
		b->count_summary[i].max += (uint64_t) rec->data.u32[pos++] << 32;
		b->count_summary[i].sum_max = rec->data.u32[pos++];
		b->count_summary[i].sum_max += (uint64_t) rec->data.u32[pos++] << 32;
	}
}

bool gcov_parse_object_summary(struct gcov_summary *b, struct gcov_record *rec)
{
	unsigned int i;

	gcov_parse_summary(b, rec);

	D(printf("object summary csum=%x\n", b->checksum));
	for (i = 0; i < GCOV_COUNTERS_SUMMABLE; i++) {
		D(printf("[%u] num=%d runs=%d sum=%" PRIu64" max=%" PRIu64 " sum_max=%" PRIu64 "\n", i,
		b->count_summary[i].num,
		b->count_summary[i].runs,
		b->count_summary[i].sum,
		b->count_summary[i].max,
		b->count_summary[i].sum_max
		));
	}
	return true;
}

bool gcov_parse_program_summary(struct gcov_summary *b, struct gcov_record *rec)
{
	unsigned int i;

	gcov_parse_summary(b, rec);

	D(printf("program summary csum=%x\n", b->checksum));
	for (i = 0; i < GCOV_COUNTERS_SUMMABLE; i++) {
		D(printf("[%u] num=%d runs=%d sum=%" PRIu64" max=%" PRIu64 " sum_max=%" PRIu64 "\n", i,
		b->count_summary[i].num,
		b->count_summary[i].runs,
		b->count_summary[i].sum,
		b->count_summary[i].max,
		b->count_summary[i].sum_max
		));
	}
	return true;
}

void gcov_reset_func_state(struct gcov_ctx *ctx)
{
	struct gcov_record_ir *rec = ctx->rec;

	free(rec->arcs);
	free(rec->lines);
	rec->arcs = NULL;
	rec->lines = NULL;
	rec->nr_arcs = 0;
	rec->nr_lines = 0;

	free(rec->blocks.flags);
	rec->blocks.nr_blocks = 0;

	free(rec->counts.counts);
	rec->counts.counts = NULL;
	rec->counts.nr_counts = 0;
}

void gcov_emit_summary(int fd, unsigned int tag, struct gcov_summary *s)
{
	struct gcov_record r;

	r.hdr.tag = tag;
	r.hdr.length = sizeof *s / 4;

	safe_write(fd, &r, sizeof r);
	safe_write(fd, s, sizeof *s);
}

void gcov_emit_counts(int fd, struct gcov_counts *c)
{
	struct gcov_record *r;

	r = safe_malloc(sizeof *r + c->nr_counts * sizeof c->counts[0]);
	r->hdr.tag = GCOV_TAG_COUNTER_BASE;
	r->hdr.length = (c->nr_counts * sizeof c->counts[0]) / 4;
	memcpy(&r->data.u32[0], &c->counts[0], (c->nr_counts * sizeof c->counts[0]));

	safe_write(fd, r, sizeof *r + c->nr_counts * sizeof c->counts[0]);
	free(r);
}


int gcov_match_line(struct gcov_ctx *ctx, struct sym_src_loc *loc,
			bool is_prologue)
{
	struct gcov_record_ir *rec = ctx->rec;
	int block_nr = -1;
	unsigned int i;

	for (i = 0; i < rec->nr_lines; i++) {
		unsigned int j;
		for (j = 0; j < rec->lines[i].nr_lines; j++) {
			const char *tmp;
			bool prologue = false;

			tmp = gcov_map_srcfilename(loc->filename,
						ctx->gcov_strip, "",
						false, "");
			if (rec->lines[i].block_no == 1 && is_prologue) {
				prologue = true;
			}

			D(printf("match prlog=%d %s:%d %s %s:%d blk=%d\n",
				prologue,
				loc->filename, loc->linenr, tmp,
				rec->lines[i].lines[j].filename,
				rec->lines[i].lines[j].lineno,
				rec->lines[i].block_no));
			if ((!strcmp(rec->lines[i].lines[j].filename,
					loc->filename)
			|| !strcmp(rec->lines[i].lines[j].filename, tmp))
			&& (rec->lines[i].lines[j].lineno == loc->linenr
			    || rec->lines[i].lines[j].lineno + prologue == loc->linenr)) {
				block_nr = rec->lines[i].block_no;
				free((void *) tmp);
				goto done;
			}
			free((void *) tmp);
		}
	}
done:
	return block_nr;
}


void gcov_process_func(struct gcov_ctx *ctx)
{
	struct gcov_record_ir *rec = ctx->rec;
	uint64_t off;
	struct sym *s;
	unsigned int num_counts = 0;
	unsigned int i;

	for (i = 0; i < rec->nr_arcs; i++) {
		struct gcov_arcs *arc = &rec->arcs[i];
		unsigned int a;

		for (a = 0; a < arc->nr_arcs; a++) {
			if (!(arc->arcs[a].flags & GCOV_ARC_ON_TREE))
				num_counts++;
		}
	}

	s = sym_lookup_by_name(ctx->store, rec->func.name);
	D(printf("Process func %s %s:%d s=%p counts=%d\n",
		rec->func.name, rec->func.source, rec->func.lineno, s,
		num_counts));

	if (s)
		sym_show("s", s);

	if (!num_counts)
		return;

	rec->counts.nr_counts = num_counts;
	rec->counts.counts = safe_mallocz(num_counts * sizeof rec->counts.counts[0]);

	if (s && s->linemap && s->cov) {
		for (off = 0; off < (s->size / 4); off++) {
			struct sym_src_loc *loc;

			loc = &s->linemap->locs[off];
			if (!loc->filename)
				continue;

			do {
				unsigned int block_nr;
				uint64_t v = 0;

				if (s->cov_ent)
					v = s->cov_ent->counter[off];

				block_nr = gcov_match_line(ctx, loc, off == 0);
				if (block_nr >= 0
					&& block_nr < rec->counts.nr_counts
					&& !rec->counts.counts[block_nr]) {
					rec->counts.counts[block_nr] = v;
				}

				/* FIXME: Prologue???   */
				if (off == 0)
					rec->counts.counts[0] = v;
				loc = loc->next;
			} while (loc);
		}
	}

	gcov_emit_counts(ctx->fd_out, &rec->counts);
}

bool gcov_parse_record(struct gcov_ctx *ctx)
{
	struct gcov_record_ir *rec = ctx->rec;
	bool r = true;

	switch (rec->rec.hdr.tag) {
	case GCOV_TAG_FUNCTION:
		D(printf("FUNCTION\n"));
		r = gcov_parse_func_record(ctx);
		break;
	case GCOV_TAG_BLOCKS:
		D(printf("BLOCKS\n"));
		r = gcov_parse_block_record(ctx);
		break;
	case GCOV_TAG_ARCS:
		D(printf("ARCS\n"));
		rec->nr_arcs++;
		rec->arcs = safe_realloc(rec->arcs,
					sizeof *rec->arcs * rec->nr_arcs);
		r = gcov_parse_arcs_record(&rec->arcs[rec->nr_arcs - 1],
					&rec->rec);
		break;
	case GCOV_TAG_LINES:
		D(printf("LINES\n"));
		rec->nr_lines++;
		rec->lines = safe_realloc(rec->lines,
					sizeof *rec->lines * rec->nr_lines);
		r = gcov_parse_lines_record(&rec->lines[rec->nr_lines - 1],
					&rec->rec);
		break;
	case GCOV_TAG_COUNTER_BASE:
		D(printf("COUNTER_BASE\n"));
		r = gcov_parse_counts_record(&rec->counts, &rec->rec);
		break;
	case GCOV_TAG_OBJECT_SUMMARY:
		D(printf("OBJ SUMMARY\n"));
		r =gcov_parse_object_summary(&rec->summary.object,
						&rec->rec);
		break;
	case GCOV_TAG_PROGRAM_SUMMARY:
		D(printf("PROGRAM SUMMARY\n"));
		r = gcov_parse_program_summary(&rec->summary.program,
						&rec->rec);
		break;
	case 0:
		D(printf("EOF\n"));
		break;
	default:
		assert(0);
		break;
	}
	return r;
}


void gcov_test(void **store, const char *gcno, const char *gcda,
		const char *gcov_strip, const char *gcov_prefix)
{
	struct gcov_summary prog_sum, obj_sum;
	struct gcov_ctx ctx;
	struct gcov_record_ir *rec;

	memset(&ctx, 0, sizeof ctx);
	ctx.store = store;
	ctx.gcov_strip = gcov_strip;
	ctx.gcov_prefix = gcov_prefix;
	ctx.rec = safe_mallocz(sizeof *rec + MAX_RECORD_SIZE);
	rec = ctx.rec;

	ctx.fd = open(gcno, O_RDONLY);
	if (ctx.fd < 0) {
		perror(gcno);
		goto err;
	}
	gcov_read_file_header(ctx.fd, &ctx.file_hdr);

	/* We dont support counter merge:ing at the moment.  */
	ctx.fd_out = -1;
	if (gcda) {
		ctx.fd_out = open(gcda, O_WRONLY | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		if (ctx.fd_out < 0) {
			perror(gcda);
			goto err;
		}
	}

	ctx.file_hdr.magic = GCOV_DATA_MAGIC;
	safe_write(ctx.fd_out, &ctx.file_hdr, sizeof ctx.file_hdr);

	while (1) {
		bool parsed;

		if (!gcov_read_record(ctx.fd, &rec->rec))
			break;

		if (rec->rec.hdr.tag == GCOV_TAG_FUNCTION) {
			/* Process previous func state.  */
			if (rec->blocks.nr_blocks) {
				gcov_process_func(&ctx);
			}
			gcov_reset_func_state(&ctx);
		}

		parsed = gcov_parse_record(&ctx);
		if (!parsed)
			break;
		switch (rec->rec.hdr.tag) {
		case GCOV_TAG_FUNCTION:
		{
			rec->rec.hdr.length = 2;
			if (ctx.file_hdr.version >= 0x34303665)
				rec->rec.hdr.length += 1;
			safe_write(ctx.fd_out, &rec->rec,
				sizeof rec->rec.hdr + rec->rec.hdr.length * 4);
			break;
		}
		case GCOV_TAG_LINES:
			if (rec->nr_arcs == rec->nr_lines) {
				gcov_process_func(&ctx);
			}
			break;
		default:
			break;
		}
	}

	if (rec->blocks.nr_blocks) {
		gcov_process_func(&ctx);
	}
	gcov_reset_func_state(&ctx);

	obj_sum.checksum = 0;
	obj_sum.count_summary[0].num = 1;
	obj_sum.count_summary[0].runs = 1;
	obj_sum.count_summary[0].sum = 1;
	obj_sum.count_summary[0].max = 1;
	obj_sum.count_summary[0].sum_max = 1;

	prog_sum.checksum = 0;
	prog_sum.count_summary[0].num = 1;
	prog_sum.count_summary[0].runs = 1;
	prog_sum.count_summary[0].sum = 1;
	prog_sum.count_summary[0].max = 1;
	prog_sum.count_summary[0].sum_max = 1;

	gcov_emit_summary(ctx.fd_out, GCOV_TAG_OBJECT_SUMMARY, &obj_sum);
	gcov_emit_summary(ctx.fd_out, GCOV_TAG_PROGRAM_SUMMARY, &prog_sum);

	/* eof.  */
	rec->rec.hdr.tag = 0;
	rec->rec.hdr.length = 0;
	safe_write(ctx.fd_out, &rec->rec,
		sizeof rec->rec.hdr + rec->rec.hdr.length * 4);
err:
	free(ctx.rec);
	close(ctx.fd);
	close(ctx.fd_out);
}

void gcov_load_gcnos(void **store, struct sym *s, size_t nr_syms,
		const char *gcov_strip, const char *gcov_prefix)
{
	unsigned int i;

	for (i = 0; i < nr_syms; i++) {
		char *gcda;
		char *gcno;

		if (!s[i].src_filename)
			continue;

		gcno = gcov_map_srcfilename(s[i].src_filename,
					gcov_strip, gcov_prefix, true, ".gcno");
		gcda = gcov_map_srcfilename(s[i].src_filename,
					gcov_strip, gcov_prefix, true, ".gcda");
		if (!gcno || !gcda)
			goto done;
		if (gcda_find_file(gcda))
			goto done;

		fprintf(stderr, "Creating %s\n", gcda);
		gcov_test(store, gcno, gcda, gcov_strip, gcov_prefix);
		//gcov_test(store, gcda, NULL, gcov_strip, gcov_prefix);
		gcda_add_file(gcda);
done:
		free(gcda);
		free(gcno);
	}
}

static void gcov_process_sym(struct sym *s, FILE *fp)
{
	uint64_t addr, end = s->addr + s->size;
	unsigned int i =  0;
	struct gcov_file *f_src, *f;

	if (!s->src_filename)
		return;
	if (!s->linemap)
		return;

	f_src = gcov_find_file_no_fail(s->src_filename, s->maxline + 1);

	i = 0;
	for (addr = s->addr; addr < end; addr += 4) {
		uint64_t v = 0;
		struct sym_src_loc *loc;

		if (s->cov_ent)
			v = s->cov_ent->counter[i];

		loc = &s->linemap->locs[i];
		if (!loc->filename)
			continue;

		do {
			unsigned int l = loc->linenr;
			if (loc->filename == s->src_filename)
				f = f_src;
			else
				f = gcov_find_file_no_fail(
						loc->filename,
						s->maxline + 1);

			assert(l < f->nr_lines);
			/* Debug info line numbers are indexed from 1.
			Some unknown entries come with ??:0  */
			if (l > 0) {
				if (v > f->lines[l - 1])
					f->lines[l - 1] += v;
				f->instr_lines[l - 1] = true;
			}

			loc = loc->next;
			gcov_file_add_sym(f, s);
		} while (loc);

		i++;
	}
}

static void gcov_emit_qcov_file(struct gcov_file *f,
			const char *gcov_strip, const char *gcov_prefix)
{
	FILE *fp = NULL, *fp_out = NULL;
	char *outname = NULL;
	unsigned int l = 0;

	fp = fopen(f->filename, "r");
	if (!fp) {
		if (strcmp("??", f->filename))
			fprintf(stderr, "unable to open %s\n", f->filename);
		return;
	}

	outname = gcov_map_srcfilename(f->filename,
                                       gcov_strip, gcov_prefix, false, ".qcov");
	printf("%s: %s\n", __func__, outname);
	if (!outname) {
		goto done;
	}

	fp_out = fopen(outname, "w+");
	if (!fp_out) {
		perror(outname);
		goto done;
	}

	fprintf(stderr, "creating %s\n", outname);

	l = 0;
	while (!feof(fp)) {
		char line[1024];
		char *s;

		s = fgets(line, sizeof line, fp);
		if (s == NULL)
			goto done;

		if (f->lines[l]) {
			fprintf(fp_out, "%8d", f->lines[l]);
		} else {
			if (f->instr_lines[l])
				fprintf(fp_out, "   #####");
			else
				fprintf(fp_out, "       -");
		}

		fprintf(fp_out, ":%5d:%s",
			l + 1, line);
		l++;
	};
	assert(l < f->nr_lines);

done:
	free(outname);
	if (fp)
		fclose(fp);
	if (fp_out)
		fclose(fp_out);
}

struct sym_src_loc *gcov_find_decl_line(struct sym *s, const char *filename)
{
	struct sym_src_loc *loc;
	struct sym_src_loc *ret = NULL;

	loc = &s->linemap->locs[0];
	if (!loc->filename)
		return ret;

	do {
		if (!strcmp(filename, loc->filename)
			&& !(loc->flags & LOC_F_INLINED)
			&& (!ret || ret->linenr > loc->linenr))
			ret = loc;
		loc = loc->next;
	} while (loc);
	return ret;
}

void lcov_emit_info(struct gcov_file *f, FILE *fp, void *exclude)
{
	unsigned int i;
	unsigned int instr_lines = 0;
	unsigned int exec_lines = 0;
	bool file_has_excludes = false;

	if (!strcmp("??", f->filename))
		return;

	fprintf(fp, "TN:\n");
	fprintf(fp, "SF:%s\n", f->filename);

	if (exclude) {
		file_has_excludes = excludes_match(exclude, f->filename, -1);
		printf("cov %s %s excludes\n", f->filename, file_has_excludes ? "has" : "has no");
	}

	if (!filename_is_likely_header(f->filename) || 1) {
		for (i = 0; i < f->nr_syms; i++) {
			struct sym_src_loc *loc;

			loc = gcov_find_decl_line(f->syms[i], f->filename);
			if (!loc) {
				continue;
			}

			fprintf(fp, "FN:%u,%s\n",
				loc->linenr, f->syms[i]->name);
			if (f->syms[i]->cov_ent) {
				fprintf(fp, "FNDA:%" PRIu64 ",%s\n",
					f->syms[i]->cov_ent->counter[0],
					f->syms[i]->name);
			}
		}
	}

	for (i = 0; i < f->nr_lines; i++) {
		if (file_has_excludes) {
			if (excludes_match(exclude, f->filename, i + 1)) {
				printf("Excluded %s : %d\n", f->filename, i);
				continue;
			}
		}

		instr_lines += f->instr_lines[i];
		if (f->instr_lines[i]) {
			exec_lines++;
			fprintf(fp, "DA:%u,%u\n", i + 1, f->lines[i]);
		}

	}
	fprintf(fp, "LF:%u\n", instr_lines);
	fprintf(fp, "LH:%u\n", exec_lines);
	fprintf(fp, "end_of_record\n");
}

void gcov_emit_gcov(void **store, struct sym *s, size_t nr_syms,
		struct sym *unknown, FILE *fp,
		const char *gcov_strip, const char *gcov_prefix,
		enum cov_format fmt,
		void *exclude)
{
	struct gcov_file *f;
	int i;

	for (i = 0; i < nr_syms; i++) {
		gcov_process_sym(&s[i], fp);
	}

	f = gcov_files;
	while (f) {
		/* OK, now go through all the files.  */
		if (fmt == QCOV)
			gcov_emit_qcov_file(f, gcov_strip, gcov_prefix);
		if (fmt == LCOV)
			lcov_emit_info(f, fp, exclude);
		f = f->next;
	}

	if (fmt == GCOV)
		gcov_load_gcnos(store, s, nr_syms, gcov_strip, gcov_prefix);
}
