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
#include <glib.h>
#include <zlib.h>

#include "util.h"
#include "address-map.h"
#include "safeio.h"
#include "syms.h"
#include "disas.h"
#include "coverage.h"
#include "trace.h"
#include "etrace.h"

#define ETRACE_MAX_VERSION_MAJOR ETRACE_VERSION_TB_EXEC

#define MAX_PKG (2 * 1024 * 1024)

struct etracer {
	struct tracer tr;
	struct etrace_info_data info;
	struct etrace_arch arch;
	struct etrace_status status;
	uint64_t filtered_execs;
	uint64_t context_errors;
	uint64_t mapping_errors;
	GHashTable *tb_defs;
	GHashTable *contexts;
	uint64_t *last_sequence;
	bool *sequence_seen;
	struct etrace_pkg *pkg;
	gzFile input;
	bool info_seen;
	bool final_status_required;
	bool final_status_seen;
	bool producer_failed;
};

struct etrace_tb_definition {
	uint64_t tb_id;
	uint64_t vaddr;
	uint64_t context_id;
	uint32_t size;
	uint16_t insn_count;
	struct etrace_tb_insn insns[];
};

static void etrace_output_exec(struct tracer *tr,
			       const struct trace_exec *exec,
			       const struct trace_exec_segment *segment,
			       void *opaque);

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

static bool etrace_v1_record(const struct etracer *t,
			     const struct etrace_pkg *pkg)
{
	if (!t->info_seen || t->info.version.major < ETRACE_VERSION_TB_EXEC)
		return etrace_invalid_pkg(pkg,
			"version 1 record without a version 1 information record");
	return true;
}

static bool etrace_validate_tb_def(const struct etrace_pkg *pkg)
{
	const struct etrace_tb_def *tb = &pkg->tb_def;
	const struct etrace_tb_insn *insns;
	const struct etrace_tb_mapping *mappings;
	size_t fixed_len = offsetof(struct etrace_tb_def, data8);
	size_t variable_len;
	size_t insn_bytes;
	size_t mapping_bytes;
	uint64_t expected_offset;
	uint16_t i;

	if (pkg->hdr.len < fixed_len)
		return etrace_invalid_pkg(pkg, "short TB definition payload");
	if (!tb->tb_id)
		return etrace_invalid_pkg(pkg, "zero TB ID");
	if (!tb->size || !tb->insn_count)
		return etrace_invalid_pkg(pkg, "empty TB definition");
	if (tb->vaddr > UINT64_MAX - tb->size)
		return etrace_invalid_pkg(pkg, "TB virtual range overflows");

	variable_len = pkg->hdr.len - fixed_len;
	insn_bytes = (size_t)tb->insn_count * sizeof(*insns);
	mapping_bytes = (size_t)tb->mapping_count * sizeof(*mappings);
	if (insn_bytes > variable_len
	    || mapping_bytes > variable_len - insn_bytes
	    || tb->code_len > variable_len - insn_bytes - mapping_bytes)
		return etrace_invalid_pkg(pkg, "TB definition arrays exceed payload");
	if (tb->code_len && tb->code_len != tb->size)
		return etrace_invalid_pkg(pkg, "partial TB code image");

	insns = (const void *)tb->data8;
	expected_offset = 0;
	for (i = 0; i < tb->insn_count; i++) {
		uint64_t end;

		if (!insns[i].size || insns[i].offset != expected_offset)
			return etrace_invalid_pkg(pkg,
				"non-contiguous TB instruction layout");
		end = (uint64_t)insns[i].offset + insns[i].size;
		if (end > tb->size)
			return etrace_invalid_pkg(pkg,
				"TB instruction exceeds virtual range");
		expected_offset = end;
	}
	if (expected_offset != tb->size)
		return etrace_invalid_pkg(pkg,
			"TB instructions do not cover virtual range");

	mappings = (const void *)(tb->data8 + insn_bytes);
	expected_offset = 0;
	for (i = 0; i < tb->mapping_count; i++) {
		uint64_t end;

		if (!mappings[i].len || mappings[i].offset != expected_offset)
			return etrace_invalid_pkg(pkg,
				"non-contiguous TB mapping layout");
		end = (uint64_t)mappings[i].offset + mappings[i].len;
		if (end > tb->size
		    || mappings[i].paddr > UINT64_MAX - mappings[i].len)
			return etrace_invalid_pkg(pkg,
				"TB mapping exceeds address range");
		expected_offset = end;
	}
	if (tb->mapping_count && expected_offset != tb->size)
		return etrace_invalid_pkg(pkg,
			"TB mappings do not cover virtual range");

	return true;
}

static bool etrace_validate_context(const struct etrace_pkg *pkg)
{
	const struct etrace_context *context = &pkg->context;
	size_t fixed_len = offsetof(struct etrace_context, data8);
	size_t remaining;
	const uint8_t *cursor;
	uint8_t i;

	if (pkg->hdr.len < fixed_len)
		return etrace_invalid_pkg(pkg, "short context payload");
	if (!context->context_id)
		return etrace_invalid_pkg(pkg, "zero context ID");

	cursor = context->data8;
	remaining = pkg->hdr.len - fixed_len;
	for (i = 0; i < context->register_count; i++) {
		const struct etrace_context_register *reg;
		size_t value_len;

		if (remaining < offsetof(struct etrace_context_register, data8))
			return etrace_invalid_pkg(pkg,
				"short context register header");
		reg = (const void *)cursor;
		value_len = (size_t)reg->name_len + reg->size;
		if (!reg->name_len || !reg->size
		    || value_len > remaining
			- offsetof(struct etrace_context_register, data8))
			return etrace_invalid_pkg(pkg,
				"context register exceeds payload");
		if (memchr(reg->data8, '\0', reg->name_len))
			return etrace_invalid_pkg(pkg,
				"context register name contains NUL");
		value_len += offsetof(struct etrace_context_register, data8);
		cursor += value_len;
		remaining -= value_len;
	}
	return true;
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
		if (t->info_seen
		    && t->info.version.major >= ETRACE_VERSION_TB_EXEC
		    && t->final_status_required
		    && pkg->hdr.len < sizeof(struct etrace_status_v1))
			return etrace_invalid_pkg(pkg,
				"short version 1 status payload");
		break;
	case TYPE_TB_DEF:
		if (!etrace_v1_record(t, pkg))
			return false;
		return etrace_validate_tb_def(pkg);
	case TYPE_TB_EXEC:
		if (!etrace_v1_record(t, pkg))
			return false;
		if (pkg->hdr.len < sizeof(pkg->tb_exec))
			return etrace_invalid_pkg(pkg, "short TB execution payload");
		break;
	case TYPE_CONTEXT:
		if (!etrace_v1_record(t, pkg))
			return false;
		return etrace_validate_context(pkg);
	case TYPE_CONTEXT_GAP:
		if (!etrace_v1_record(t, pkg))
			return false;
		if (pkg->hdr.len < sizeof(pkg->context_gap))
			return etrace_invalid_pkg(pkg, "short context gap payload");
		if (pkg->context_gap.reason != ETRACE_CONTEXT_GAP_FILTERED)
			return etrace_invalid_pkg(pkg, "unknown context gap reason");
		if (!pkg->context_gap.filtered_execs)
			return etrace_invalid_pkg(pkg, "empty context gap");
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
		"versions through %u.x\n", t->info.version.major,
		t->info.version.minor,
		ETRACE_MAX_VERSION_MAJOR);
	exit(1);
}

void etrace_process_info(struct etracer *t)
{
	t->info = t->pkg->info;
	t->info_seen = true;
	if (t->info.attr & ETRACE_INFO_F_FINAL_STATUS)
		t->final_status_required = true;

	/* Validate version.  */
	if (t->info.version.major > ETRACE_MAX_VERSION_MAJOR)
		bad_version(t);
}

static void etrace_process_status(struct etracer *t)
{
	struct etrace_status *status = &t->pkg->status;
	const struct etrace_status_v1 *status_v1 =
		(const void *)&t->pkg->status;
	bool have_v1 = t->pkg->hdr.len >= sizeof(*status_v1);

	t->status = *status;
	t->final_status_seen = true;
	t->producer_failed = !(status->flags & ETRACE_STATUS_F_COMPLETE)
		|| status->unresolved_tb_exits
		|| status->unresolved_discontinuities
		|| status->unresolved_vcpu_exits
		|| status->output_errors;
	if (have_v1) {
		t->filtered_execs = status_v1->filtered_execs;
		t->context_errors = status_v1->context_errors;
		t->mapping_errors = status_v1->mapping_errors;
		t->producer_failed = t->producer_failed
			|| status_v1->context_errors
			|| status_v1->mapping_errors;
	}

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
		if (have_v1) {
			fprintf(t->tr.fp_out,
				"S1 filtered-exec=%" PRIu64
				" context-errors=%" PRIu64
				" mapping-errors=%" PRIu64 "\n",
				status_v1->filtered_execs,
				status_v1->context_errors,
				status_v1->mapping_errors);
		}
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

static bool etrace_process_tb_def(struct etracer *t)
{
	const struct etrace_tb_def *tb = &t->pkg->tb_def;
	struct etrace_tb_definition *definition;
	const struct etrace_tb_insn *insns = (const void *)tb->data8;
	size_t alloc_size = sizeof(*definition)
		+ (size_t)tb->insn_count * sizeof(definition->insns[0]);

	if (g_hash_table_contains(t->tb_defs, &tb->tb_id))
		return etrace_invalid_pkg(t->pkg, "duplicate TB ID");

	definition = safe_malloc(alloc_size);
	definition->tb_id = tb->tb_id;
	definition->vaddr = tb->vaddr;
	definition->context_id = tb->context_id;
	definition->size = tb->size;
	definition->insn_count = tb->insn_count;
	memcpy(definition->insns, insns,
	       (size_t)tb->insn_count * sizeof(definition->insns[0]));
	g_hash_table_insert(t->tb_defs, &definition->tb_id, definition);

	if (t->tr.fp_out) {
		const struct etrace_tb_mapping *mappings = (const void *)(
			tb->data8 + (size_t)tb->insn_count * sizeof(*insns));
		uint16_t i;

		fprintf(t->tr.fp_out,
			"T id=%" PRIx64 " virt=%" PRIx64 "-%" PRIx64
			" context=%" PRIx64 " insns=%u mappings=%u",
			tb->tb_id, tb->vaddr, tb->vaddr + tb->size,
			tb->context_id, tb->insn_count, tb->mapping_count);
		for (i = 0; i < tb->mapping_count; i++) {
			fprintf(t->tr.fp_out,
				" map=%" PRIx64 "-%" PRIx64 ":%" PRIx64,
				tb->vaddr + mappings[i].offset,
				tb->vaddr + mappings[i].offset + mappings[i].len,
				mappings[i].paddr);
		}
		fputc('\n', t->tr.fp_out);
	}

	return true;
}

static bool etrace_process_tb_exec(struct etracer *t, enum cov_format cov_fmt)
{
	const struct etrace_tb_exec *tb_exec = &t->pkg->tb_exec;
	struct etrace_tb_definition *definition;
	struct trace_exec exec;
	uint16_t last;

	definition = g_hash_table_lookup(t->tb_defs, &tb_exec->tb_id);
	if (!definition)
		return etrace_invalid_pkg(t->pkg, "undefined TB ID");
	if (tb_exec->context_id
	    && !g_hash_table_contains(t->contexts, &tb_exec->context_id))
		return etrace_invalid_pkg(t->pkg, "undefined context ID");
	if (!tb_exec->insn_count
	    || tb_exec->insn_count > definition->insn_count)
		return etrace_invalid_pkg(t->pkg,
			"invalid dispatched instruction count");
	if (t->sequence_seen[t->pkg->hdr.unit_id]
	    && tb_exec->sequence
		!= t->last_sequence[t->pkg->hdr.unit_id] + 1)
		return etrace_invalid_pkg(t->pkg,
			"non-consecutive per-vCPU sequence");
	t->sequence_seen[t->pkg->hdr.unit_id] = true;
	t->last_sequence[t->pkg->hdr.unit_id] = tb_exec->sequence;

	last = tb_exec->insn_count - 1;
	exec = (struct trace_exec) {
		.time = tb_exec->time,
		.start = definition->vaddr,
		.end = definition->vaddr + definition->insns[last].offset
			+ definition->insns[last].size,
		.tb_id = tb_exec->tb_id,
		.context_id = tb_exec->context_id,
		.duration = tb_exec->duration,
		.unit_id = t->pkg->hdr.unit_id,
		.flags = tb_exec->flags,
	};
	trace_process_exec(&t->tr, cov_fmt, &exec, etrace_output_exec, NULL);
	return true;
}

static bool etrace_process_context(struct etracer *t)
{
	const struct etrace_context *context = &t->pkg->context;
	const uint8_t *cursor = context->data8;
	uint64_t *id;
	uint8_t i;

	if (g_hash_table_contains(t->contexts, &context->context_id))
		return etrace_invalid_pkg(t->pkg, "duplicate context ID");
	id = safe_malloc(sizeof(*id));
	*id = context->context_id;
	g_hash_table_add(t->contexts, id);

	if (t->tr.fp_out) {
		fprintf(t->tr.fp_out,
			"C%u id=%" PRIx64 " pc=%" PRIx64 " as=%" PRIx64
			" vm=%" PRIx64 " privilege=%u flags=%x registers=%u",
			t->pkg->hdr.unit_id, context->context_id, context->pc,
			context->address_space_id, context->virtual_machine_id,
			context->privilege, context->flags,
			context->register_count);
		for (i = 0; i < context->register_count; i++) {
			const struct etrace_context_register *reg =
				(const void *)cursor;
			const uint8_t *name = reg->data8;
			const uint8_t *value = name + reg->name_len;
			int byte;

			fprintf(t->tr.fp_out, " %.*s=0x", reg->name_len,
				(const char *)name);
			if (t->arch.guest.big_endian) {
				for (byte = 0; byte < reg->size; byte++)
					fprintf(t->tr.fp_out, "%02x", value[byte]);
			} else {
				for (byte = reg->size - 1; byte >= 0; byte--)
					fprintf(t->tr.fp_out, "%02x", value[byte]);
			}
			cursor += offsetof(struct etrace_context_register, data8)
				+ reg->name_len + reg->size;
		}
		fputc('\n', t->tr.fp_out);
	}
	return true;
}

static bool etrace_process_context_gap(struct etracer *t)
{
	const struct etrace_context_gap *gap = &t->pkg->context_gap;

	if (!(t->info.attr & ETRACE_INFO_F_FILTERED))
		return etrace_invalid_pkg(t->pkg,
			"context gap in an unfiltered trace");
	if (gap->from_context_id
	    && !g_hash_table_contains(t->contexts, &gap->from_context_id))
		return etrace_invalid_pkg(t->pkg, "undefined source context ID");
	if (gap->to_context_id
	    && !g_hash_table_contains(t->contexts, &gap->to_context_id))
		return etrace_invalid_pkg(t->pkg,
			"undefined destination context ID");
	if (t->sequence_seen[t->pkg->hdr.unit_id]
	    && gap->sequence != t->last_sequence[t->pkg->hdr.unit_id] + 1)
		return etrace_invalid_pkg(t->pkg,
			"non-consecutive per-vCPU sequence");
	t->sequence_seen[t->pkg->hdr.unit_id] = true;
	t->last_sequence[t->pkg->hdr.unit_id] = gap->sequence;

	if (t->tr.fp_out) {
		fprintf(t->tr.fp_out,
			"G%u sequence=%" PRIu64 " from=%" PRIx64 " to=%" PRIx64
			" filtered=%" PRIu64 " reason=%u flags=%x\n",
			t->pkg->hdr.unit_id, gap->sequence,
			gap->from_context_id, gap->to_context_id,
			gap->filtered_execs, gap->reason, gap->flags);
	}
	return true;
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

static void etrace_output_exec(struct tracer *tr,
			       const struct trace_exec *exec,
			       const struct trace_exec_segment *segment,
			       void *opaque)
{
	struct sym *sym = segment->sym;

	(void) opaque;
	if (!tr->fp_out)
		return;

	if (segment->mapped
	    && segment->runtime_start != segment->linked_start) {
		fprintf(tr->fp_out,
			"E%" PRIx32 " runtime=%" PRIx64 "-%" PRIx64
			" linked=%" PRIx64 "-%" PRIx64 "%s%s\n",
			exec->unit_id, segment->runtime_start,
			segment->runtime_end, segment->linked_start,
			segment->linked_end, sym ? " " : "", sym ? sym->name : "");
	} else {
		char out[80] = "E";
		unsigned int pos = 1;

		pos += u64tohex(out + pos, exec->unit_id);
		out[pos++] = ' ';
		pos += u64tohex(out + pos, segment->linked_start);
		out[pos++] = ' ';
		pos += u64tohex(out + pos, segment->linked_end);
		if (sym) {
			unsigned int namelen = sym->namelen;

			out[pos++] = ' ';
			if (namelen + pos + 1 > sizeof(out))
				namelen = sizeof(out) - pos - 1;
			memcpy(&out[pos], sym->name, namelen);
			pos += namelen;
		}
		out[pos++] = '\n';
		fwrite(out, 1, pos, tr->fp_out);
	}
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
		struct trace_exec exec = {
			.time = now,
			.unit_id = t->pkg->hdr.unit_id,
		};

		switch (t->arch.guest.arch_bits) {
		case 32:
			exec.start = ex->t32[i].start;
			exec.end = ex->t32[i].end;
			exec.duration = ex->t32[i].duration;
			break;
		case 64:
			exec.start = ex->t64[i].start;
			exec.end = ex->t64[i].end;
			exec.duration = ex->t64[i].duration;
			break;
		default:
			assert(0);
			break;
		}

		if (cov_fmt != NONE
		    && t->info.attr & ETRACE_INFO_F_TB_CHAINING) {
			fprintf(stderr,
				"Cannot do coverage on a trace with TB chaining.\n"
				"Rerun QEMU with -no-tb-chain.\n");
			exit(EXIT_FAILURE);
		}
		trace_process_exec(&t->tr, cov_fmt, &exec, etrace_output_exec,
				   NULL);
		now += exec.duration;
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
	t.tb_defs = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, free);
	t.contexts = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
	t.last_sequence = calloc(UINT16_MAX + 1, sizeof(*t.last_sequence));
	t.sequence_seen = calloc(UINT16_MAX + 1, sizeof(*t.sequence_seen));
	if (!t.last_sequence || !t.sequence_seen) {
		fprintf(stderr, "Unable to allocate ETrace sequence state\n");
		exit(EXIT_FAILURE);
	}

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
		case TYPE_TB_DEF:
			if (!etrace_process_tb_def(&t)) {
				g_hash_table_destroy(t.tb_defs);
				free(t.pkg);
				exit(EXIT_FAILURE);
			}
			break;
		case TYPE_TB_EXEC:
			if (!etrace_process_tb_exec(&t, cov_fmt)) {
				g_hash_table_destroy(t.tb_defs);
				free(t.pkg);
				exit(EXIT_FAILURE);
			}
			break;
		case TYPE_CONTEXT:
			if (!etrace_process_context(&t)) {
				g_hash_table_destroy(t.contexts);
				g_hash_table_destroy(t.tb_defs);
				free(t.pkg);
				exit(EXIT_FAILURE);
			}
			break;
		case TYPE_CONTEXT_GAP:
			if (!etrace_process_context_gap(&t)) {
				g_hash_table_destroy(t.contexts);
				g_hash_table_destroy(t.tb_defs);
				free(t.pkg);
				exit(EXIT_FAILURE);
			}
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
	g_hash_table_destroy(t.contexts);
	g_hash_table_destroy(t.tb_defs);
	free(t.sequence_seen);
	free(t.last_sequence);
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
			" write-errors=%" PRIu64
			" context-errors=%" PRIu64
			" mapping-errors=%" PRIu64 "\n",
			t.status.unresolved_tb_exits,
			t.status.unresolved_discontinuities,
			t.status.unresolved_vcpu_exits,
			t.status.output_errors,
			t.context_errors,
			t.mapping_errors);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "done.\n");
}
