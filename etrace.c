/*
 * ETrace decoding.
 * Written by Edgar E. Iglesias.
 */
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

#include "util.h"
#include "safeio.h"
#include "syms.h"
#include "disas.h"
#include "coverage.h"
#include "etrace.h"

#define MAX_PKG (2 * 1024 * 1024)

struct etracer {
	int fd;
	FILE *fp_out;
	void **sym_tree;

	struct etrace_info_data info;

	struct {
		const char *objdump;
		const char *machine;
	} host, guest;

	struct etrace_pkg *pkg;
};

static bool etrace_read_hdr(int fd, struct etrace_hdr *hdr)
{
	ssize_t r;

	r = safe_read(fd, hdr, sizeof *hdr);
	if (r != sizeof *hdr)
		return false;
	return true;
}

static bool etrace_read_pkg(struct etracer *t, struct etrace_pkg *pkg)
{
	ssize_t r;

	if (!etrace_read_hdr(t->fd, &pkg->hdr))
		return false;

	if (pkg->hdr.len > MAX_PKG) {
		printf("Too large Etrace pkg! %d\n", pkg->hdr.len);
		return false;
	}

	r = safe_read(t->fd, &pkg->u8[0], pkg->hdr.len);
	if (r != pkg->hdr.len)
		return false;

	return true;
}

void etrace_process_info(struct etracer *t)
{
	t->info = t->pkg->info;

	if (t->fp_out) {
		fprintf(t->fp_out, "guest arch=%d %dbit\n",
			t->info.guest.arch_id, t->info.guest.arch_bits);
		fprintf(t->fp_out, "host arch=%d %dbit\n",
			t->info.host.arch_id, t->info.host.arch_bits);
	}
}

void etrace_process_tb(struct etracer *t)
{
	struct etrace_pkg *pkg = t->pkg;

	if (!t->fp_out)
		return;

	if (t->guest.machine) {
		fprintf(t->fp_out, "guest virt=%" PRIx64 " phys=%" PRIx64 "\n",
			pkg->tb.vaddr, pkg->tb.paddr);
		disas(t->fp_out, t->guest.objdump, t->guest.machine,
			t->info.guest.big_endian,
			pkg->tb.vaddr, &pkg->tb.data8[0],
			pkg->tb.guest_code_len);
		fputc('\n', t->fp_out);
	}

	if (t->host.machine) {
		fprintf(t->fp_out, "host\n");
		disas(t->fp_out, t->host.objdump, t->host.machine,
			t->info.host.big_endian,
			pkg->tb.host_addr,
			&pkg->tb.data8[pkg->tb.guest_code_len],
			pkg->tb.host_code_len);
		fputc('\n', t->fp_out);
	}
}

static inline int hexchar(unsigned int val)
{
        val &= 0xf;
        if (val > 9)
                return val - 10 + 'a';
        return val + '0';
}

unsigned int u64tohex(char *out, uint64_t v)
{
	char tmp[16];
	unsigned int len = 0;
	int i;

	if (!v) {
		*out = '0';
		return 1;
	}

	while (v) {
		tmp[len] = hexchar(v);
		v >>= 4;
		len++;
	}
	for (i = 0; i < len; i++)
		out[len - i - 1] = tmp[i];
	return len;
}

unsigned int u64todec(char *out, uint64_t v)
{
	char tmp[24];
	unsigned int len = 0;
	unsigned int r;
	int i;

	if (!v) {
		*out = '0';
		return 1;
	}

	while (v) {
		r = v % 10;
		tmp[len] = '0' + r;
		v /= 10;
		len++;
	}
	for (i = 0; i < len; i++)
		out[len - i - 1] = tmp[i];
	return len;
}

void etrace_process_exec(struct etracer *t, enum cov_format cov_fmt)
{
	unsigned int len;
	unsigned int i;
	uint64_t start_time = t->pkg->ex.start_time;
	uint64_t now = start_time;
	size_t ent_size;
	struct etrace_exec *ex = &t->pkg->ex;

	if (t->info.guest.arch_bits == 32)
		ent_size = sizeof ex->t32[0];
	else if (t->info.guest.arch_bits == 32)
		ent_size = sizeof ex->t64[0];
	else
		assert(0);


	len = t->pkg->hdr.len;
	len /= ent_size;

	for (i = 0; i < len; i++) {
		struct sym *sym = NULL;
		uint64_t start, end;
		uint32_t duration;

		switch (t->info.guest.arch_bits) {
		case 32:
			start = ex->t32[i].start;
			end = ex->t32[i].end;
			duration = ex->t32[i].duration;
			break;
		case 64:
			start = ex->t64[i].start;
			end = ex->t64[i].end;
			duration = ex->t64[i].duration;
			break;
		default:
			assert(0);
			break;
		}

		if (t && t->sym_tree && *t->sym_tree)
			sym = sym_lookup_by_addr(t->sym_tree, start);

		if (t->fp_out) {
#if 0
			printf("Trace %"PRIx64  " %" PRIx64 " - %" PRIx64 " ",
				now, start, end);
#else
			char out[80] = "E";
			unsigned int pos = 1;

			pos += u64tohex(out + pos, t->pkg->hdr.unit_id);
			out[pos++] = ' ';

			/* time stamp.  */
			pos += u64todec(out + pos, now);
			out[pos++] = ' ';

			pos += u64tohex(out + pos, start);
			out[pos++] = ' ';
			pos += u64tohex(out + pos, end);
			if (sym) {
				unsigned int namelen = sym->namelen;
				out[pos++] = ' ';

				if ((namelen + pos + 1) > sizeof out)
					namelen = sizeof out - pos - 1;
				memcpy(&out[pos], sym->name, namelen);
				pos += namelen;
			}
			out[pos++] = '\n';
			fwrite(&out, 1, pos, t->fp_out);
#endif
		}

		if (cov_fmt != NONE) {
                        if (t->info.attr & ETRACE_INFO_F_TB_CHAINING) {
				fprintf(stderr,
					"Cannot do coverage on a trace with "
					"TB chaining.\n"
					"Rerun QEMU with -no-tb-chain.\n");
				exit(EXIT_FAILURE);
                        }
			if (!sym)
				sym = sym_get_unknown(t->sym_tree);

			sym_update_cov(sym, start, end, duration);
		}
		now += duration;
	}
}

void etrace_process_note(struct etracer *t)
{
	struct etrace_note *nt = &t->pkg->note;
	if (!t->fp_out)
		return;

	t->pkg->u8[t->pkg->hdr.len] = 0;
	fprintf(t->fp_out, "%s", &nt->data8[0]);
}

void etrace_process_mem(struct etracer *t)
{
	struct etrace_mem *mem = &t->pkg->mem;
	if (!t->fp_out)
		return;

	fprintf(t->fp_out, "M%u %" PRIu64 " %c %" PRIx64 " %" PRIx64 "\n",
		t->pkg->hdr.unit_id,
		mem->time, mem->attr & MEM_WRITE ? 'w' : 'r', mem->paddr,
		mem->value);
}

void etrace_show(int fd, FILE *fp_out,
		 const char *objdump, const char *machine,
		 const char *guest_objdump, const char *guest_machine,
		 void **sym_tree, enum cov_format cov_fmt)
{
	struct etracer t;

	fprintf(stderr, "Processing trace\n");

	t.fd = fd;
	t.fp_out = fp_out;
	t.sym_tree = sym_tree;
	t.host.objdump = objdump;
	t.host.machine = machine;
	t.guest.objdump = guest_objdump;
	t.guest.machine = guest_machine;

	t.pkg = safe_malloc(sizeof t.pkg->hdr + MAX_PKG);

	while (etrace_read_pkg(&t, t.pkg)) {
		switch (t.pkg->hdr.type) {
		case TYPE_EXEC:
			etrace_process_exec(&t, cov_fmt);
			break;
		case TYPE_TB:
			etrace_process_tb(&t);
			break;
		case TYPE_NOTE:
			etrace_process_note(&t);
			break;
		case TYPE_MEM:
			etrace_process_mem(&t);
			break;
		case TYPE_INFO:
			etrace_process_info(&t);
			break;
		default:
			assert(0);
			break;
		}
	}
	free(t.pkg);
	fprintf(stderr, "done.\n");
}
