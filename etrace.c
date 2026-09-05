/*
 * ETrace decoding.
 *
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
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <zlib.h>

#include "util.h"
#include "address-map.h"
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
	struct etrace_status status;
	struct etrace_pkg *pkg;
	gzFile input;
	bool final_status_required;
	bool final_status_seen;
	bool producer_failed;
};

static ssize_t etrace_read(struct etracer *t, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t total = 0;

	while (total < len) {
		unsigned int chunk = len - total > UINT_MAX
			? UINT_MAX : (unsigned int)(len - total);
		int ret = gzread(t->input, p + total, chunk);

		if (ret < 0) {
			int error;
			const char *message = gzerror(t->input, &error);

			fprintf(stderr, "ETrace input: %s\n", message);
			return -1;
		}
		if (ret == 0)
			break;
		total += (size_t)ret;
	}
	return total;
}

static bool etrace_read_hdr(struct etracer *t, struct etrace_hdr *hdr)
{
	ssize_t r;

	r = etrace_read(t, hdr, sizeof *hdr);
	if (r == 0)
		return false;
	if (r < 0)
		exit(EXIT_FAILURE);
	if (r != sizeof *hdr) {
		fprintf(stderr, "Unexpected end of ETrace header\n");
		exit(EXIT_FAILURE);
	}
	return true;
}

static bool etrace_read_pkg(struct etracer *t, struct etrace_pkg *pkg)
{
	ssize_t r;

	if (!etrace_read_hdr(t, &pkg->hdr))
		return false;

	if (pkg->hdr.len > MAX_PKG) {
		fprintf(stderr, "ETrace package is too large: %u\n",
			pkg->hdr.len);
		exit(EXIT_FAILURE);
	}

	r = etrace_read(t, &pkg->u8[0], pkg->hdr.len);
	if (r < 0)
		exit(EXIT_FAILURE);
	if (r != pkg->hdr.len) {
		fprintf(stderr, "Unexpected end of ETrace payload\n");
		exit(EXIT_FAILURE);
	}

	return true;
}

static bool etrace_invalid_pkg(const struct etrace_pkg *pkg,
			       const char *reason)
{
	fprintf(stderr, "Invalid ETrace package type %u, length %u: %s\n",
		pkg->hdr.type, pkg->hdr.len, reason);
	return false;
}

static bool etrace_names_valid(const uint8_t *names, size_t available,
			       uint16_t dev_name_len,
			       uint16_t event_name_len)
{
	size_t names_len = (size_t) dev_name_len + event_name_len;

	if (dev_name_len == 0 || event_name_len == 0 || names_len > available)
		return false;
	return names[dev_name_len - 1] == '\0'
		&& names[names_len - 1] == '\0';
}

static bool etrace_validate_pkg(struct etracer *t)
{
	struct etrace_pkg *pkg = t->pkg;
	size_t fixed_len;
	size_t code_len;
	size_t ent_size;

	switch (pkg->hdr.type) {
	case TYPE_INFO:
		if (pkg->hdr.len < sizeof(pkg->info))
			return etrace_invalid_pkg(pkg, "short info payload");
		break;
	case TYPE_ARCH:
		if (pkg->hdr.len < sizeof(pkg->arch))
			return etrace_invalid_pkg(pkg, "short architecture payload");
		break;
	case TYPE_EXEC:
		if (pkg->hdr.len < sizeof(pkg->ex.start_time))
			return etrace_invalid_pkg(pkg, "short execution payload");
		if (t->arch.guest.arch_bits == 32)
			ent_size = sizeof(pkg->ex.t32[0]);
		else if (t->arch.guest.arch_bits == 64)
			ent_size = sizeof(pkg->ex.t64[0]);
		else
			return etrace_invalid_pkg(pkg, "missing guest architecture");
		if ((pkg->hdr.len - sizeof(pkg->ex.start_time)) % ent_size)
			return etrace_invalid_pkg(pkg, "partial execution entry");
		break;
	case TYPE_TB:
		fixed_len = offsetof(struct etrace_tb, data8);
		if (pkg->hdr.len < fixed_len)
			return etrace_invalid_pkg(pkg, "short translation block payload");
		code_len = (size_t) pkg->tb.guest_code_len
			+ pkg->tb.host_code_len;
		if (code_len > pkg->hdr.len - fixed_len)
			return etrace_invalid_pkg(pkg, "translation block code exceeds payload");
		if ((t->tr.guest.machine || t->tr.host.machine)
		    && t->arch.guest.arch_bits != 32
		    && t->arch.guest.arch_bits != 64)
			return etrace_invalid_pkg(pkg, "missing architecture for disassembly");
		break;
	case TYPE_NOTE:
		if (pkg->hdr.len < sizeof(pkg->note.time))
			return etrace_invalid_pkg(pkg, "short note payload");
		break;
	case TYPE_MEM:
		if (pkg->hdr.len < sizeof(pkg->mem))
			return etrace_invalid_pkg(pkg, "short memory payload");
		break;
	case TYPE_OLD_EVENT_U64:
		fixed_len = offsetof(struct etrace_old_event_u64, names);
		if (pkg->hdr.len < fixed_len)
			return etrace_invalid_pkg(pkg, "short legacy event payload");
		if (!etrace_names_valid(pkg->old_event_u64.names,
				pkg->hdr.len - fixed_len,
				pkg->old_event_u64.dev_name_len,
				pkg->old_event_u64.event_name_len))
			return etrace_invalid_pkg(pkg, "invalid legacy event names");
		break;
	case TYPE_EVENT_U64:
		fixed_len = offsetof(struct etrace_event_u64, names);
		if (pkg->hdr.len < fixed_len)
			return etrace_invalid_pkg(pkg, "short event payload");
		if (!etrace_names_valid(pkg->event_u64.names,
				pkg->hdr.len - fixed_len,
				pkg->event_u64.dev_name_len,
				pkg->event_u64.event_name_len))
			return etrace_invalid_pkg(pkg, "invalid event names");
		break;
	case TYPE_DISCONTINUITY:
		if (pkg->hdr.len < sizeof(pkg->discontinuity))
			return etrace_invalid_pkg(pkg,
						  "short discontinuity payload");
		if (pkg->discontinuity.kind > ETRACE_DISCONTINUITY_HOST_CALL)
			return etrace_invalid_pkg(pkg,
						  "unknown discontinuity kind");
		break;
	case TYPE_STATUS:
		if (pkg->hdr.len < sizeof(pkg->status))
			return etrace_invalid_pkg(pkg, "short status payload");
		break;
	default:
		break;
	}
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
	if (t->info.attr & ETRACE_INFO_F_FINAL_STATUS)
		t->final_status_required = true;

	/* Validate version.  */
	if (t->info.version.major > ETRACE_MIN_VERSION_MAJOR)
		bad_version(t);
}

static void etrace_process_status(struct etracer *t)
{
	struct etrace_status *status = &t->pkg->status;

	t->status = *status;
	t->final_status_seen = true;
	t->producer_failed = !(status->flags & ETRACE_STATUS_F_COMPLETE)
		|| status->unresolved_tb_exits
		|| status->unresolved_discontinuities
		|| status->unresolved_vcpu_exits
		|| status->output_errors;

	if (t->tr.fp_out) {
		fprintf(t->tr.fp_out,
			"S complete=%u unresolved-tb=%" PRIu64
			" unresolved-discontinuity=%" PRIu64
			" unresolved-vcpu=%" PRIu64
			" write-errors=%" PRIu64
			" discontinuity-pc-mismatches=%" PRIu64 "\n",
			!!(status->flags & ETRACE_STATUS_F_COMPLETE),
			status->unresolved_tb_exits,
			status->unresolved_discontinuities,
			status->unresolved_vcpu_exits,
			status->output_errors,
			status->discontinuity_pc_mismatches);
	}
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
	/* Initialize it to avoid false compiler warnings.  */
	char tmp[16] = {0};
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
	else if (t->arch.guest.arch_bits == 64)
		ent_size = sizeof ex->t64[0];
	else
		assert(0);


	len = t->pkg->hdr.len - sizeof(ex->start_time);
	len /= ent_size;

	for (i = 0; i < len; i++) {
		uint64_t start, end;
		uint32_t duration;
		uint64_t cursor;
		uint64_t accounted = 0;
		uint64_t total_len;

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

		cursor = start;
		total_len = end >= start ? end - start : 0;
		while (cursor < end) {
			struct address_map_segment segment;
			struct sym *sym = NULL;
			uint32_t segment_duration;
			uint64_t segment_len;

			if (!address_map_next_segment(t->tr.address_map, &cursor, end,
						      &segment))
				break;
			segment_len = segment.runtime_end - segment.runtime_start;
			if (segment.runtime_end == end) {
				segment_duration = duration - accounted;
			} else {
				segment_duration = total_len
					? (uint32_t)(((__uint128_t)duration * segment_len)
						     / total_len) : 0;
				accounted += segment_duration;
			}

			if (t->tr.sym_tree && *t->tr.sym_tree)
				sym = sym_lookup_by_addr(t->tr.sym_tree,
							 segment.linked_start);

			if (t->tr.fp_out && segment.mapped
			    && segment.runtime_start != segment.linked_start) {
				fprintf(t->tr.fp_out,
					"E%" PRIx16 " runtime=%" PRIx64 "-%" PRIx64
					" linked=%" PRIx64 "-%" PRIx64 "%s%s\n",
					(unsigned int)t->pkg->hdr.unit_id,
					segment.runtime_start, segment.runtime_end,
					segment.linked_start, segment.linked_end,
					sym ? " " : "", sym ? sym->name : "");
			} else if (t->tr.fp_out) {
#if 0
			printf("Trace %"PRIx64  " %" PRIx64 " - %" PRIx64 " ",
				now, segment.linked_start, segment.linked_end);
#else
			char out[80] = "E";
			unsigned int pos = 1;

			pos += u64tohex(out + pos, t->pkg->hdr.unit_id);
			out[pos++] = ' ';

			/* time stamp.  */
#if 0
			pos += u64todec(out + pos, now);
			out[pos++] = ' ';
#endif
			pos += u64tohex(out + pos, segment.linked_start);
			out[pos++] = ' ';
			pos += u64tohex(out + pos, segment.linked_end);
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

			if (cov_fmt == NONE)
				continue;
                        if (t->info.attr & ETRACE_INFO_F_TB_CHAINING) {
				fprintf(stderr,
					"Cannot do coverage on a trace with "
					"TB chaining.\n"
					"Rerun QEMU with -no-tb-chain.\n");
					exit(EXIT_FAILURE);
			        }
			if (t->tr.sym_tree && *t->tr.sym_tree)
				sym_update_image_cov(t->tr.sym_tree,
					segment.linked_start, segment.linked_end);
			if (!sym)
				sym = sym_get_unknown(t->tr.sym_tree);

			if (sym) {
				uint64_t addr = segment.linked_start;
				while (sym && addr < segment.linked_end) {
					uint64_t tend = segment.linked_end;

					if (tend > (sym->addr + sym->size)) {
						tend = sym->addr + sym->size;
						printf("WARNING: fixup sym %s has spans over to another symbol\n", sym->name);
					}
					sym_update_cov(sym, addr, tend, segment_duration);
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
	size_t len;

	if (!t->tr.fp_out)
		return;

	len = t->pkg->hdr.len - sizeof(nt->time);
	fwrite(&nt->data8[0], 1, len, t->tr.fp_out);
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
	struct etrace_old_event_u64 *event = &t->pkg->old_event_u64;
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

static const char *discontinuity_kind_name(uint32_t kind)
{
	switch (kind) {
	case ETRACE_DISCONTINUITY_UNKNOWN:
		return "unknown";
	case ETRACE_DISCONTINUITY_INTERRUPT:
		return "interrupt";
	case ETRACE_DISCONTINUITY_EXCEPTION:
		return "exception";
	case ETRACE_DISCONTINUITY_HOST_CALL:
		return "host-call";
	default:
		return "invalid";
	}
}

void etrace_process_discontinuity(struct etracer *t)
{
	struct etrace_discontinuity *discontinuity = &t->pkg->discontinuity;

	if (!t->tr.fp_out)
		return;

	fprintf(t->tr.fp_out, "D%u %s %" PRIx64 " %" PRIx64 " flags=%x\n",
		t->pkg->hdr.unit_id,
		discontinuity_kind_name(discontinuity->kind),
		discontinuity->from_pc, discontinuity->to_pc,
		discontinuity->flags);
}

void etrace_show(int fd, FILE *fp_out,
		 const char *objdump, const char *machine,
		 const char *guest_objdump, const char *guest_machine,
		 void **sym_tree, enum cov_format cov_fmt,
		 enum trace_format trace_in_fmt,
		 enum trace_format trace_out_fmt,
		 const struct address_map *address_map)
{
	struct etracer t = { 0 };
	bool unknown_pkg_warn = false;
	int fd_out = -1;

	fprintf(stderr, "Processing trace\n");

	t.tr.fd = fd;
	t.tr.fp_out = fp_out;
	t.tr.out_fmt = trace_out_fmt;
	t.tr.sym_tree = sym_tree;
	t.tr.address_map = address_map;
	t.tr.host.objdump = objdump;
	t.tr.host.machine = machine;
	t.tr.guest.objdump = guest_objdump;
	t.tr.guest.machine = guest_machine;
	t.input = gzdopen(dup(fd), "rb");
	if (!t.input) {
		fprintf(stderr, "Unable to open ETrace input\n");
		exit(EXIT_FAILURE);
	}
	if (gzbuffer(t.input, 128 * 1024) != 0) {
		fprintf(stderr, "Unable to allocate ETrace input buffer\n");
		exit(EXIT_FAILURE);
	}

	t.pkg = safe_malloc(sizeof t.pkg->hdr + MAX_PKG);

	/* Short path for passthrough.  */
	if (trace_out_fmt == trace_in_fmt) {
		if (t.tr.fp_out) {
			fd_out = fileno(t.tr.fp_out);
			t.tr.fp_out = NULL;
		}
	}

	while (etrace_read_pkg(&t, t.pkg)) {
		int r;

		if (t.final_status_seen) {
			etrace_invalid_pkg(t.pkg, "record after final status");
			free(t.pkg);
			exit(EXIT_FAILURE);
		}
		if (!etrace_validate_pkg(&t)) {
			free(t.pkg);
			exit(EXIT_FAILURE);
		}

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
		case TYPE_DISCONTINUITY:
			etrace_process_discontinuity(&t);
			break;
		case TYPE_STATUS:
			etrace_process_status(&t);
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

		if (fd_out != -1) {
			r = safe_write(fd_out, t.pkg,
					sizeof t.pkg->hdr + t.pkg->hdr.len);
			if (r <= 0) {
				/* Don't bail out as coverage may still work.  */
				static bool once = false;
				if (!once) {
					fprintf(stderr, "trace-out: %s pid=%d\n",
						strerror(errno), getpid());
					once = true;
					sleep(1000);
				}
				if (cov_fmt != NONE) {
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	free(t.pkg);
	if (gzclose(t.input) != Z_OK) {
		fprintf(stderr, "Unable to finish ETrace input\n");
		exit(EXIT_FAILURE);
	}
	if (t.final_status_required && !t.final_status_seen) {
		fprintf(stderr, "ETrace is missing its final producer status\n");
		exit(EXIT_FAILURE);
	}
	if (t.producer_failed) {
		fprintf(stderr,
			"ETrace producer reported invalid execution data: "
			"unresolved-tb=%" PRIu64
			" unresolved-discontinuity=%" PRIu64
			" unresolved-vcpu=%" PRIu64
			" write-errors=%" PRIu64 "\n",
			t.status.unresolved_tb_exits,
			t.status.unresolved_discontinuities,
			t.status.unresolved_vcpu_exits,
			t.status.output_errors);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "done.\n");
}
