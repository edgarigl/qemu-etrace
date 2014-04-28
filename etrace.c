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
#include "trace.h"
#include "etrace.h"

#define ETRACE_MIN_VERSION_MAJOR 0

#define MAX_PKG (2 * 1024 * 1024)

struct etracer {
	struct tracer tr;
	struct etrace_info_data info;
	struct etrace_arch arch;
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

	if (!etrace_read_hdr(t->tr.fd, &pkg->hdr))
		return false;

	if (pkg->hdr.len > MAX_PKG) {
		printf("Too large Etrace pkg! %d\n", pkg->hdr.len);
		return false;
	}

	r = safe_read(t->tr.fd, &pkg->u8[0], pkg->hdr.len);
	if (r != pkg->hdr.len)
		return false;

	return true;
}

static void bad_version(struct etracer *t)
{
	fprintf(stderr,
		"Trace-file has version %u.%u but qemu-etrace only supports "
		"%u.x\n", t->info.version.major, t->info.version.minor,
		ETRACE_MIN_VERSION_MAJOR);
	exit(1);
}

void etrace_process_info(struct etracer *t)
{
	t->info = t->pkg->info;

	/* Validate version.  */
	if (t->info.version.major > ETRACE_MIN_VERSION_MAJOR)
		bad_version(t);
}

void etrace_process_arch(struct etracer *t)
{
	t->arch = t->pkg->arch;

	if (t->tr.fp_out) {
		fprintf(t->tr.fp_out, "guest arch=%d %dbit\n",
			t->arch.guest.arch_id, t->arch.guest.arch_bits);
		fprintf(t->tr.fp_out, "host arch=%d %dbit\n",
			t->arch.host.arch_id, t->arch.host.arch_bits);
	}
}

void etrace_process_tb(struct etracer *t)
{
	struct etrace_pkg *pkg = t->pkg;

	if (!t->tr.fp_out)
		return;

	if (t->tr.guest.machine) {
		fprintf(t->tr.fp_out,
                        "guest virt=%" PRIx64 " phys=%" PRIx64 "\n",
			pkg->tb.vaddr, pkg->tb.paddr);
		disas(t->tr.fp_out, t->tr.guest.objdump, t->tr.guest.machine,
			t->arch.guest.big_endian,
			pkg->tb.vaddr, &pkg->tb.data8[0],
			pkg->tb.guest_code_len);
		fputc('\n', t->tr.fp_out);
	}

	if (t->tr.host.machine) {
		fprintf(t->tr.fp_out, "host\n");
		disas(t->tr.fp_out, t->tr.host.objdump, t->tr.host.machine,
			t->arch.host.big_endian,
			pkg->tb.host_addr,
			&pkg->tb.data8[pkg->tb.guest_code_len],
			pkg->tb.host_code_len);
		fputc('\n', t->tr.fp_out);
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

	if (t->arch.guest.arch_bits == 32)
		ent_size = sizeof ex->t32[0];
	else if (t->arch.guest.arch_bits == 32)
		ent_size = sizeof ex->t64[0];
	else
		assert(0);


	len = t->pkg->hdr.len;
	len /= ent_size;

	for (i = 0; i < len; i++) {
		struct sym *sym = NULL;
		uint64_t start, end;
		uint32_t duration;

		switch (t->arch.guest.arch_bits) {
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

		if (t && t->tr.sym_tree && *t->tr.sym_tree)
			sym = sym_lookup_by_addr(t->tr.sym_tree, start);

		if (t->tr.fp_out) {
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
			fwrite(&out, 1, pos, t->tr.fp_out);
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
				sym = sym_get_unknown(t->tr.sym_tree);

			if (sym) {
				uint64_t addr = start;
				while (sym && addr < end) {
					uint32_t tend = end;

					if (tend > (sym->addr + sym->size)) {
						tend = sym->addr + sym->size;
						printf("WARNING: fixup sym %s has spans over to another symbol\n", sym->name);
					}
					sym_update_cov(sym, addr, tend, duration);
					addr = tend;
					sym = sym_lookup_by_addr(t->tr.sym_tree, addr);
				}
			}
		}
		now += duration;
	}
}

void etrace_process_note(struct etracer *t)
{
	struct etrace_note *nt = &t->pkg->note;
	if (!t->tr.fp_out)
		return;

	t->pkg->u8[t->pkg->hdr.len] = 0;
	fprintf(t->tr.fp_out, "%s", &nt->data8[0]);
}

void etrace_process_mem(struct etracer *t)
{
	struct etrace_mem *mem = &t->pkg->mem;
	if (!t->tr.fp_out)
		return;

	fprintf(t->tr.fp_out, "M%u %" PRIu64 " %c %" PRIx64 " %" PRIx64 "\n",
		t->pkg->hdr.unit_id,
		mem->time, mem->attr & MEM_WRITE ? 'w' : 'r', mem->paddr,
		mem->value);
}

void etrace_process_old_event_u64(struct etracer *t)
{
	struct etrace_event_u64 *event = &t->pkg->event_u64;
	if (!t->tr.fp_out)
		return;

	fprintf(t->tr.fp_out, "EV %" PRIu64 " %u %s.%s %" PRIu64 "\n",
		event->time, event->unit_id,
		event->names, event->names + event->dev_name_len, event->val);
}

void etrace_process_event_u64(struct etracer *t)
{
	struct etrace_event_u64 *event = &t->pkg->event_u64;
	if (!t->tr.fp_out)
		return;

	fprintf(t->tr.fp_out, "EV %" PRIu64 " %u %s.%s %" PRIu64 "\n",
		event->time, event->unit_id,
		event->names, event->names + event->dev_name_len, event->val);
}

void etrace_show(int fd, FILE *fp_out,
		 const char *objdump, const char *machine,
		 const char *guest_objdump, const char *guest_machine,
		 void **sym_tree, enum cov_format cov_fmt,
		 enum trace_format trace_fmt)
{
	struct etracer t;
	bool unknown_pkg_warn = false;

	fprintf(stderr, "Processing trace\n");

	t.tr.fd = fd;
	t.tr.fp_out = fp_out;
	t.tr.sym_tree = sym_tree;
	t.tr.host.objdump = objdump;
	t.tr.host.machine = machine;
	t.tr.guest.objdump = guest_objdump;
	t.tr.guest.machine = guest_machine;

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
		case TYPE_ARCH:
			etrace_process_arch(&t);
			break;
		case TYPE_BARRIER:
			/* We dont yet support queueing and sorting of
			   pkgs. Ignore.  */
			break;
		case TYPE_INFO:
			etrace_process_info(&t);
			break;
		case TYPE_OLD_EVENT_U64:
			etrace_process_old_event_u64(&t);
			break;
		case TYPE_EVENT_U64:
			etrace_process_event_u64(&t);
			break;
		default:
			/* Show a warning once. We trust the version handling
			   to abort when the format is truly incompatible.  */
			if (!unknown_pkg_warn) {
				fprintf(stderr,
					"Non-fatal warning: "
					"Unknown etrace package type %u\n"
					"Maybe you need to update "
					"qemu-etrace?\n",
					t.pkg->hdr.type);
				unknown_pkg_warn = true;
			}
			break;
		}
	}
	free(t.pkg);
	fprintf(stderr, "done.\n");
}
