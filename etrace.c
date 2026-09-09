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
#include "elf-context.h"
#include "trace.h"
#include "etrace.h"
#include "etrace-hash.h"
#include "event-journal.h"

#define ETRACE_MAX_VERSION_MAJOR ETRACE_VERSION_TB_EXEC

#define MAX_PKG (2 * 1024 * 1024)

/* Index granularity, independent of the guest's translation granule. */
#define BINDING_INDEX_SHIFT 12

struct etracer {
	struct tracer tr;
	struct etrace_info_data info;
	struct etrace_arch arch;
	struct etrace_status status;
	uint64_t filtered_execs;
	uint64_t context_errors;
	uint64_t mapping_errors;
	uint64_t code_errors;
	GHashTable *tb_defs;
	GHashTable *contexts;
	const struct elf_context *elf_context;
	GArray *physical_bindings;
	GHashTable *binding_buckets;
	bool binding_conflict;
	bool auto_map;
	size_t unresolved_limit;
	size_t unresolved_entries;
	uint64_t unresolved_events;
	uint64_t resolved_events;
	uint64_t ambiguous_tbs;
	uint64_t code_candidates;
	FILE *event_spool;
	struct event_journal *journal;
	uint64_t journal_counts[3];
	uint64_t journal_reported;
	uint64_t ordered_unresolved;
	uint64_t inferred_image_mappings;
	bool preserve_order;
	uint64_t *last_sequence;
	bool *sequence_seen;
	struct etrace_pkg *pkg;
	gzFile input;
	bool info_seen;
	bool final_status_required;
	bool final_status_seen;
	bool status_v1_seen;
	bool producer_failed;
};

struct etrace_tb_definition {
	uint64_t tb_id;
	uint64_t vaddr;
	uint64_t linked_vaddr;
	uint64_t context_id;
	uint64_t code_hash;
	uint32_t size;
	uint16_t insn_count;
	uint16_t mapping_count;
	struct etrace_tb_insn *insns;
	struct etrace_tb_mapping *mappings;
	uint8_t *code;
	GArray *pending;
	bool resolved;
	bool code_searched;
	bool code_candidate;
	bool mapping_anchor;
	bool bindings_seeded;
	bool infer_image_mapping;
};

struct pending_tb_exec {
	uint64_t context_id;
	uint64_t count;
	uint64_t duration;
	uint64_t first_time;
	uint32_t unit_id;
	uint16_t insn_count;
	uint16_t flags;
};

struct physical_binding {
	uint64_t physical_start;
	uint64_t physical_end;
	uint64_t linked_start;
	bool ambiguous;
};

struct observed_context {
	uint16_t architecture;
	uint8_t privilege;
	uint32_t flags;
};

static void etrace_output_exec(struct tracer *tr,
			       const struct trace_exec *exec,
			       const struct trace_exec_segment *segment,
			       void *opaque);
static bool etrace_invalid_pkg(const struct etrace_pkg *pkg,
			       const char *reason);

static bool context_matches_elf(const struct etracer *t, uint64_t context_id)
{
	const struct observed_context *context;

	if (!t->elf_context || !t->elf_context->configured)
		return true;
	if (!context_id)
		return false;
	context = g_hash_table_lookup(t->contexts, &context_id);
	return context && elf_context_matches(t->elf_context,
		context->architecture, context->privilege, context->flags);
}

static void etrace_tb_definition_free(void *opaque)
{
	struct etrace_tb_definition *definition = opaque;

	if (!definition)
		return;
	if (definition->pending)
		g_array_free(definition->pending, true);
	free(definition->code);
	free(definition->mappings);
	free(definition->insns);
	free(definition);
}

static void etrace_report_journal(struct etracer *t, const char *phase)
{
	struct event_journal_stats stats;

	event_journal_get_stats(t->journal, &stats);
	fprintf(stderr, "Ordered journal %s: tb-exec=%" PRIu64
		" context-gap=%" PRIu64 " discontinuity=%" PRIu64
		" logical=%" PRIu64 " stored=%" PRIu64 " frames=%" PRIu64
		" buffered-logical=%zu reserved=%zu\n",
		phase, t->journal_counts[0], t->journal_counts[1],
		t->journal_counts[2], stats.logical_bytes, stats.stored_bytes,
		stats.frames, stats.buffered_logical_bytes, stats.reserved_bytes);
	t->journal_reported = stats.logical_bytes;
}

static bool etrace_spool_event(struct etracer *t)
{
	size_t len = sizeof(t->pkg->hdr) + t->pkg->hdr.len;
	struct event_journal_stats stats;

	if (!event_journal_append(t->journal, t->pkg, len))
		return etrace_invalid_pkg(t->pkg, event_journal_error(t->journal));
	switch (t->pkg->hdr.type) {
	case TYPE_TB_EXEC:
		t->journal_counts[0]++;
		break;
	case TYPE_CONTEXT_GAP:
		t->journal_counts[1]++;
		break;
	case TYPE_DISCONTINUITY:
		t->journal_counts[2]++;
		break;
	}
	event_journal_get_stats(t->journal, &stats);
	if (stats.logical_bytes - t->journal_reported >= UINT64_C(64) * 1024 * 1024)
		etrace_report_journal(t, "capture");
	return true;
}

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
	if (!tb->code_len && tb->code_hash)
		return etrace_invalid_pkg(pkg, "TB hash without code image");
	if (tb->code_len) {
		const uint8_t *code = tb->data8 + insn_bytes + mapping_bytes;

		if (etrace_code_hash(code, tb->code_len) != tb->code_hash)
			return etrace_invalid_pkg(pkg, "TB code hash mismatch");
	}

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
		if (t->auto_map)
			return etrace_invalid_pkg(pkg,
				"automatic mapping requires TB execution records");
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

static void etrace_output_status(struct etracer *t)
{
	const struct etrace_status *status = &t->status;

	if (!t->tr.fp_out)
		return;
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
	if (t->status_v1_seen) {
		fprintf(t->tr.fp_out,
			"S1 filtered-exec=%" PRIu64
			" context-errors=%" PRIu64
			" mapping-errors=%" PRIu64
			" code-errors=%" PRIu64 "\n",
			t->filtered_execs, t->context_errors,
			t->mapping_errors, t->code_errors);
	}
}

static void etrace_process_status(struct etracer *t)
{
	struct etrace_status *status = &t->pkg->status;
	const struct etrace_status_v1 *status_v1 =
		(const void *)&t->pkg->status;
	bool have_v1 = t->pkg->hdr.len >= sizeof(*status_v1);

	t->status = *status;
	t->final_status_seen = true;
	t->status_v1_seen = have_v1;
	t->producer_failed = !(status->flags & ETRACE_STATUS_F_COMPLETE)
		|| status->unresolved_tb_exits
		|| status->unresolved_discontinuities
		|| status->unresolved_vcpu_exits
		|| status->output_errors;
	if (have_v1) {
		t->filtered_execs = status_v1->filtered_execs;
		t->context_errors = status_v1->context_errors;
		t->mapping_errors = status_v1->mapping_errors;
		t->code_errors = status_v1->code_errors;
		t->producer_failed = t->producer_failed
			|| status_v1->context_errors
			|| status_v1->mapping_errors
			|| status_v1->code_errors;
	}

	if (!t->preserve_order)
		etrace_output_status(t);
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

static void etrace_emit_tb_execution(struct etracer *t,
				     const struct etrace_tb_definition *definition,
				     const struct pending_tb_exec *pending,
				     enum cov_format cov_fmt)
{
	struct tracer linked_tracer = t->tr;
	uint16_t last = pending->insn_count - 1;
	struct trace_exec exec = {
		.time = pending->first_time,
		.start = definition->resolved ? definition->linked_vaddr
			: definition->vaddr,
		.end = (definition->resolved ? definition->linked_vaddr
			: definition->vaddr) + definition->insns[last].offset
			+ definition->insns[last].size,
		.tb_id = definition->tb_id,
		.context_id = pending->context_id,
		.duration = pending->duration,
		.count = pending->count,
		.unit_id = pending->unit_id,
		.flags = pending->flags,
	};

	if (t->auto_map && definition->resolved) {
		linked_tracer.address_map = NULL;
		trace_process_exec(&linked_tracer, cov_fmt, &exec,
				   etrace_output_exec, NULL);
	} else {
		trace_process_exec(&t->tr, cov_fmt, &exec, etrace_output_exec,
				   NULL);
	}
}

static bool binding_lookup(const struct etracer *t, uint64_t physical_start,
			   uint64_t len, uint64_t *linked_start)
{
	uint64_t first_bucket, last_bucket;
	uint64_t bucket, candidate = 0;
	unsigned int first_match = G_MAXUINT;
	bool found = false;

	if (!len || physical_start > UINT64_MAX - len)
		return false;
	first_bucket = physical_start >> BINDING_INDEX_SHIFT;
	last_bucket = (physical_start + len - 1) >> BINDING_INDEX_SHIFT;
	if (!g_hash_table_contains(t->binding_buckets, &first_bucket)
	    || !g_hash_table_contains(t->binding_buckets, &last_bucket))
		return false;
	for (bucket = first_bucket; bucket <= last_bucket; bucket++) {
		const GArray *indices = g_hash_table_lookup(t->binding_buckets,
							  &bucket);
		unsigned int i;

		if (!indices)
			continue;
		for (i = 0; i < indices->len; i++) {
			unsigned int index = g_array_index(indices, unsigned int, i);
			const struct physical_binding *binding;

			/* Keep the original binding order across bucket boundaries. */
			if (index >= first_match)
				break;
			binding = &g_array_index(t->physical_bindings,
						struct physical_binding, index);
			if (binding->ambiguous
			    && physical_start < binding->physical_end
			    && physical_start + len > binding->physical_start) {
				first_match = index;
				found = false;
				break;
			}
			if (physical_start >= binding->physical_start
			    && physical_start + len <= binding->physical_end) {
				first_match = index;
				candidate = binding->linked_start
					+ physical_start - binding->physical_start;
				found = true;
				break;
			}
		}
	}
	if (found)
		*linked_start = candidate;
	return found;
}

static bool add_physical_binding(struct etracer *t, uint64_t physical_start,
				 uint64_t len, uint64_t linked_start)
{
	struct physical_binding binding = { 0 };
	uint64_t bucket, last_bucket;
	unsigned int i, index;

	if (!len || physical_start > UINT64_MAX - len
	    || linked_start > UINT64_MAX - len)
		return false;
	binding.physical_start = physical_start;
	binding.physical_end = physical_start + len;
	binding.linked_start = linked_start;
	for (i = 0; i < t->physical_bindings->len; i++) {
		struct physical_binding *existing = &g_array_index(
			t->physical_bindings, struct physical_binding, i);
		uint64_t overlap;

		if (binding.physical_end <= existing->physical_start
		    || binding.physical_start >= existing->physical_end)
			continue;
		overlap = binding.physical_start > existing->physical_start
			? binding.physical_start : existing->physical_start;
		if (binding.linked_start + overlap - binding.physical_start
		    != existing->linked_start + overlap
			- existing->physical_start) {
			existing->ambiguous = true;
			t->binding_conflict = true;
			t->ambiguous_tbs++;
			return false;
		}
		if (binding.physical_start == existing->physical_start
		    && binding.physical_end == existing->physical_end
		    && binding.linked_start == existing->linked_start)
			return false;
	}
	g_array_append_val(t->physical_bindings, binding);
	index = t->physical_bindings->len - 1;
	last_bucket = (binding.physical_end - 1) >> BINDING_INDEX_SHIFT;
	for (bucket = binding.physical_start >> BINDING_INDEX_SHIFT;
	     bucket <= last_bucket; bucket++) {
		GArray *indices = g_hash_table_lookup(t->binding_buckets, &bucket);

		if (!indices) {
			uint64_t *key = safe_malloc(sizeof(*key));

			*key = bucket;
			indices = g_array_new(false, false, sizeof(index));
			g_hash_table_insert(t->binding_buckets, key, indices);
		}
		g_array_append_val(indices, index);
	}
	return true;
}

static bool translate_relative(uint64_t value, uint64_t input_anchor,
			       uint64_t output_anchor, uint64_t *translated)
{
	if (value >= input_anchor) {
		uint64_t offset = value - input_anchor;

		if (output_anchor > UINT64_MAX - offset)
			return false;
		*translated = output_anchor + offset;
	} else {
		uint64_t offset = input_anchor - value;

		if (output_anchor < offset)
			return false;
		*translated = output_anchor - offset;
	}
	return true;
}

static const struct sym_load_segment *find_load_segment(
	const struct sym_load_segment *segments, size_t count,
	uint64_t linked_start, uint64_t len)
{
	size_t i;

	if (!len || linked_start > UINT64_MAX - len)
		return NULL;
	for (i = 0; i < count; i++) {
		const struct sym_load_segment *segment = &segments[i];

		if (linked_start >= segment->linked_start
		    && linked_start + len <= segment->linked_start
			+ segment->memory_size)
			return segment;
	}
	return NULL;
}

static bool seed_image_bindings(struct etracer *t,
				struct etrace_tb_definition *definition)
{
	const struct sym_load_segment *segments;
	const struct sym_load_segment *anchor_segment;
	const struct etrace_tb_mapping *anchor_mapping;
	struct physical_binding *bindings;
	uint64_t anchor_linked;
	uint64_t anchor_image;
	uint64_t existing_linked;
	size_t count;
	size_t i;

	segments = sym_get_executable_load_segments(t->tr.sym_tree, &count);
	if (!segments || !count || !definition->mapping_count)
		return false;
	anchor_mapping = &definition->mappings[0];
	anchor_linked = definition->linked_vaddr + anchor_mapping->offset;
	anchor_segment = find_load_segment(segments, count, anchor_linked,
					  anchor_mapping->len);
	if (!anchor_segment)
		return false;
	anchor_image = anchor_segment->image_start
		+ anchor_linked - anchor_segment->linked_start;
	if (binding_lookup(t, anchor_mapping->paddr, anchor_mapping->len,
			   &existing_linked)
	    && existing_linked == anchor_linked)
		return true;

	/* Every observed piece of the anchor must describe one load bias. */
	for (i = 0; i < definition->mapping_count; i++) {
		const struct etrace_tb_mapping *mapping = &definition->mappings[i];
		const struct sym_load_segment *segment;
		uint64_t linked = definition->linked_vaddr + mapping->offset;
		uint64_t image;
		uint64_t physical;

		segment = find_load_segment(segments, count, linked, mapping->len);
		if (!segment)
			return false;
		image = segment->image_start + linked - segment->linked_start;
		if (!translate_relative(image, anchor_image, anchor_mapping->paddr,
					&physical)
		    || physical != mapping->paddr)
			return false;
	}

	bindings = safe_malloc(count * sizeof(*bindings));
	for (i = 0; i < count; i++) {
		if (!translate_relative(segments[i].image_start, anchor_image,
					anchor_mapping->paddr,
					&bindings[i].physical_start)
		    || bindings[i].physical_start
			> UINT64_MAX - segments[i].memory_size) {
			free(bindings);
			return false;
		}
		bindings[i].physical_end = bindings[i].physical_start
			+ segments[i].memory_size;
		bindings[i].linked_start = segments[i].linked_start;
	}
	for (i = 0; i < count; i++) {
		add_physical_binding(t, bindings[i].physical_start,
			bindings[i].physical_end - bindings[i].physical_start,
			bindings[i].linked_start);
	}
	free(bindings);
	t->inferred_image_mappings++;
	return true;
}

static void seed_physical_bindings(struct etracer *t,
				   struct etrace_tb_definition *definition)
{
	uint16_t i;

	if (definition->bindings_seeded)
		return;
	if (definition->infer_image_mapping
	    && seed_image_bindings(t, definition)) {
		definition->bindings_seeded = true;
		return;
	}
	for (i = 0; i < definition->mapping_count; i++) {
		const struct etrace_tb_mapping *mapping = &definition->mappings[i];

		add_physical_binding(t, mapping->paddr, mapping->len,
			definition->linked_vaddr + mapping->offset);
	}
	definition->bindings_seeded = true;
}

static bool resolve_from_physical(const struct etracer *t,
				  const struct etrace_tb_definition *definition,
				  uint64_t *linked_vaddr)
{
	uint64_t candidate = 0;
	uint16_t i;

	if (!definition->mapping_count)
		return false;
	for (i = 0; i < definition->mapping_count; i++) {
		const struct etrace_tb_mapping *mapping = &definition->mappings[i];
		uint64_t linked;
		uint64_t base;

		if (!binding_lookup(t, mapping->paddr, mapping->len, &linked)
		    || linked < mapping->offset)
			return false;
		base = linked - mapping->offset;
		if (i && base != candidate)
			return false;
		candidate = base;
	}
	*linked_vaddr = candidate;
	return true;
}

static bool resolve_tb_definition(struct etracer *t,
				  struct etrace_tb_definition *definition)
{
	uint64_t linked = definition->vaddr;
	uint64_t mapped_end;
	bool explicit_map;
	bool trusted_code = false;

	if (definition->resolved)
		return false;
	explicit_map = address_map_translate(t->tr.address_map,
					     definition->vaddr, &linked);
	if (explicit_map) {
		uint64_t runtime_end = definition->vaddr + definition->size - 1;

		if (!address_map_translate(t->tr.address_map, runtime_end,
					   &mapped_end)
		    || mapped_end - linked != definition->size - 1)
			explicit_map = false;
	}
	if (linked <= UINT64_MAX - definition->size
	    && (explicit_map || linked == definition->vaddr)
	    && sym_range_is_executable(t->tr.sym_tree, linked,
					linked + definition->size)) {
		trusted_code = definition->code
			&& sym_code_matches(t->tr.sym_tree, linked,
					    definition->code, definition->size);
		if (definition->code && !trusted_code)
			return false;
		definition->resolved = true;
		definition->linked_vaddr = linked;
	} else if (resolve_from_physical(t, definition, &linked)
		   && linked <= UINT64_MAX - definition->size
		   && sym_range_is_executable(t->tr.sym_tree, linked,
					      linked + definition->size)
		   && definition->code
		   && sym_code_matches(t->tr.sym_tree, linked,
					    definition->code, definition->size)) {
		definition->resolved = true;
		definition->linked_vaddr = linked;
	} else if (!definition->code_searched && definition->code
		   && definition->size >= 8) {
		size_t count = sym_find_code_matches(t->tr.sym_tree,
			definition->code, definition->size, NULL, 0);

		definition->code_searched = true;
		if (count == 1) {
			/* Equal bytes alone do not establish image ownership. */
			definition->code_candidate = true;
			t->code_candidates++;
		} else if (count > 1) {
			t->ambiguous_tbs++;
		}
	}
	if (!definition->resolved)
		return false;

	if (definition->code_candidate) {
		definition->code_candidate = false;
		t->code_candidates--;
	}
	if (trusted_code) {
		definition->mapping_anchor = true;
		definition->infer_image_mapping = !explicit_map
			&& t->elf_context && t->elf_context->configured;
		if (explicit_map || !t->elf_context
		    || !t->elf_context->configured)
			seed_physical_bindings(t, definition);
	}
	return true;
}

static void replay_pending(struct etracer *t,
			   struct etrace_tb_definition *definition,
			   enum cov_format cov_fmt)
{
	unsigned int i;

	if (!definition->resolved || !definition->pending)
		return;
	for (i = 0; i < definition->pending->len; i++) {
		const struct pending_tb_exec *pending = &g_array_index(
			definition->pending, struct pending_tb_exec, i);

		etrace_emit_tb_execution(t, definition, pending, cov_fmt);
		t->resolved_events += pending->count;
		t->unresolved_events -= pending->count;
	}
	t->unresolved_entries -= definition->pending->len;
	g_array_set_size(definition->pending, 0);
}

static void resolve_pending_definitions(struct etracer *t,
					enum cov_format cov_fmt)
{
	bool changed;

	do {
		GHashTableIter iter;
		void *value;

		changed = false;
		g_hash_table_iter_init(&iter, t->tb_defs);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			struct etrace_tb_definition *definition = value;

			if (resolve_tb_definition(t, definition)) {
				replay_pending(t, definition, cov_fmt);
				changed = true;
			}
		}
	} while (changed);
}

static bool etrace_process_tb_def(struct etracer *t, enum cov_format cov_fmt)
{
	const struct etrace_tb_def *tb = &t->pkg->tb_def;
	struct etrace_tb_definition *definition;
	const struct etrace_tb_insn *insns = (const void *)tb->data8;
	const struct etrace_tb_mapping *mappings = (const void *)(
		tb->data8 + (size_t)tb->insn_count * sizeof(*insns));
	const uint8_t *code = (const uint8_t *)&mappings[tb->mapping_count];

	if (g_hash_table_contains(t->tb_defs, &tb->tb_id))
		return etrace_invalid_pkg(t->pkg, "duplicate TB ID");

	definition = safe_mallocz(sizeof(*definition));
	definition->tb_id = tb->tb_id;
	definition->vaddr = tb->vaddr;
	definition->context_id = tb->context_id;
	definition->code_hash = tb->code_hash;
	definition->size = tb->size;
	definition->insn_count = tb->insn_count;
	definition->mapping_count = tb->mapping_count;
	definition->insns = safe_malloc(
		(size_t)tb->insn_count * sizeof(definition->insns[0]));
	memcpy(definition->insns, insns,
	       (size_t)tb->insn_count * sizeof(definition->insns[0]));
	if (tb->mapping_count) {
		definition->mappings = safe_malloc(
			(size_t)tb->mapping_count * sizeof(definition->mappings[0]));
		memcpy(definition->mappings, mappings,
		       (size_t)tb->mapping_count * sizeof(definition->mappings[0]));
	}
	if (tb->code_len) {
		definition->code = safe_malloc(tb->code_len);
		memcpy(definition->code, code, tb->code_len);
	}
	if (!t->auto_map) {
		definition->resolved = true;
		definition->linked_vaddr = definition->vaddr;
	}
	g_hash_table_insert(t->tb_defs, &definition->tb_id, definition);

	if (t->tr.fp_out) {
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
	if (t->auto_map) {
		resolve_pending_definitions(t, cov_fmt);
		if (t->binding_conflict)
			return etrace_invalid_pkg(t->pkg,
				"conflicting physical image mappings");
		replay_pending(t, definition, cov_fmt);
	}

	return true;
}

static bool append_pending_execution(struct etracer *t,
				     struct etrace_tb_definition *definition,
				     const struct etrace_tb_exec *tb_exec)
{
	unsigned int i;

	if (!definition->pending) {
		definition->pending = g_array_new(false, true,
						  sizeof(struct pending_tb_exec));
	}
	for (i = 0; i < definition->pending->len; i++) {
		struct pending_tb_exec *pending = &g_array_index(
			definition->pending, struct pending_tb_exec, i);

		if (pending->context_id != tb_exec->context_id
		    || pending->unit_id != t->pkg->hdr.unit_id
		    || pending->insn_count != tb_exec->insn_count
		    || pending->flags != tb_exec->flags)
			continue;
		if (pending->count == UINT64_MAX
		    || pending->duration > UINT64_MAX - tb_exec->duration)
			return etrace_invalid_pkg(t->pkg,
				"unresolved execution aggregate overflows");
		pending->count++;
		pending->duration += tb_exec->duration;
		t->unresolved_events++;
		return true;
	}
	if (t->unresolved_entries >= t->unresolved_limit)
		return etrace_invalid_pkg(t->pkg,
			"unresolved execution limit exceeded");
	{
		struct pending_tb_exec pending = {
			.context_id = tb_exec->context_id,
			.count = 1,
			.duration = tb_exec->duration,
			.first_time = tb_exec->time,
			.unit_id = t->pkg->hdr.unit_id,
			.insn_count = tb_exec->insn_count,
			.flags = tb_exec->flags,
		};

		g_array_append_val(definition->pending, pending);
	}
	t->unresolved_entries++;
	t->unresolved_events++;
	return true;
}

static bool etrace_process_tb_exec(struct etracer *t, enum cov_format cov_fmt)
{
	const struct etrace_tb_exec *tb_exec = &t->pkg->tb_exec;
	struct etrace_tb_definition *definition;
	struct pending_tb_exec execution;

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
	if (definition->mapping_anchor && !definition->bindings_seeded
	    && context_matches_elf(t, tb_exec->context_id)) {
		seed_physical_bindings(t, definition);
		if (t->auto_map)
			resolve_pending_definitions(t, cov_fmt);
		if (t->binding_conflict)
			return etrace_invalid_pkg(t->pkg,
				"conflicting physical image mappings");
	}

	if (t->preserve_order)
		return etrace_spool_event(t);
	if (!context_matches_elf(t, tb_exec->context_id))
		return true;
	if (t->auto_map && !definition->resolved)
		return append_pending_execution(t, definition, tb_exec);
	execution = (struct pending_tb_exec) {
		.context_id = tb_exec->context_id,
		.count = 1,
		.duration = tb_exec->duration,
		.first_time = tb_exec->time,
		.unit_id = t->pkg->hdr.unit_id,
		.insn_count = tb_exec->insn_count,
		.flags = tb_exec->flags,
	};
	etrace_emit_tb_execution(t, definition, &execution, cov_fmt);
	return true;
}

static bool etrace_process_context(struct etracer *t)
{
	const struct etrace_context *context = &t->pkg->context;
	const uint8_t *cursor = context->data8;
	struct observed_context *observed;
	uint64_t *id;
	uint8_t i;

	if (g_hash_table_contains(t->contexts, &context->context_id))
		return etrace_invalid_pkg(t->pkg, "duplicate context ID");
	id = safe_malloc(sizeof(*id));
	observed = safe_malloc(sizeof(*observed));
	*id = context->context_id;
	*observed = (struct observed_context) {
		.architecture = context->architecture,
		.privilege = context->privilege,
		.flags = context->flags,
	};
	g_hash_table_insert(t->contexts, id, observed);

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

	if (t->preserve_order)
		return etrace_spool_event(t);
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

static void etrace_output_context_gap(struct etracer *t, uint16_t unit_id,
				      const struct etrace_context_gap *gap)
{
	if (t->tr.fp_out) {
		fprintf(t->tr.fp_out,
			"G%u sequence=%" PRIu64 " from=%" PRIx64 " to=%" PRIx64
			" filtered=%" PRIu64 " reason=%u flags=%x\n",
			unit_id, gap->sequence,
			gap->from_context_id, gap->to_context_id,
			gap->filtered_execs, gap->reason, gap->flags);
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

static bool etrace_replay_ordered_events(struct etracer *t,
					 enum cov_format cov_fmt)
{
	struct etrace_hdr hdr;
	ssize_t got;
	uint64_t counts[3] = { 0 };
	uint64_t replayed_bytes = 0, reported_bytes = 0;

	if (!event_journal_rewind(t->journal)) {
		fprintf(stderr, "Ordered event spool: %s\n",
			event_journal_error(t->journal));
		return false;
	}
	etrace_report_journal(t, "replay-start");
	while ((got = event_journal_read(t->journal, &hdr, sizeof(hdr))) > 0) {
		if (got != sizeof(hdr)) {
			fprintf(stderr, "Truncated ordered event spool header\n");
			return false;
		}
		if (hdr.len > MAX_PKG) {
			fprintf(stderr, "Ordered event spool record is too large\n");
			return false;
		}
		t->pkg->hdr = hdr;
		if (event_journal_read(t->journal, t->pkg->u8, hdr.len) != hdr.len) {
			fprintf(stderr, "Ordered event spool: %s\n",
				event_journal_error(t->journal) ?
				event_journal_error(t->journal) : "truncated record");
			return false;
		}
		switch (hdr.type) {
		case TYPE_TB_EXEC:
		{
			const struct etrace_tb_exec *tb_exec = &t->pkg->tb_exec;
			struct etrace_tb_definition *definition;

			counts[0]++;

			if (hdr.len < sizeof(*tb_exec)) {
				fprintf(stderr, "Short ordered TB execution record\n");
				return false;
			}
			definition = g_hash_table_lookup(t->tb_defs,
						 &tb_exec->tb_id);
			if (!definition) {
				fprintf(stderr, "Ordered event references undefined TB\n");
				return false;
			}
			if (definition->resolved
			    && context_matches_elf(t, tb_exec->context_id)) {
				struct pending_tb_exec execution = {
					.context_id = tb_exec->context_id,
					.count = 1,
					.duration = tb_exec->duration,
					.first_time = tb_exec->time,
					.unit_id = hdr.unit_id,
					.insn_count = tb_exec->insn_count,
					.flags = tb_exec->flags,
				};

				etrace_emit_tb_execution(t, definition, &execution,
							 cov_fmt);
			} else {
				t->ordered_unresolved++;
				if (t->tr.fp_out) {
					fprintf(t->tr.fp_out,
						"U%u sequence=%" PRIu64
						" tb=%" PRIx64 " context=%" PRIx64
						" insns=%u\n",
						hdr.unit_id, tb_exec->sequence,
						tb_exec->tb_id, tb_exec->context_id,
						tb_exec->insn_count);
				}
			}
			break;
		}
		case TYPE_CONTEXT_GAP:
			counts[1]++;
			if (hdr.len < sizeof(t->pkg->context_gap)) {
				fprintf(stderr, "Short ordered context gap record\n");
				return false;
			}
			etrace_output_context_gap(t, hdr.unit_id,
						  &t->pkg->context_gap);
			break;
		case TYPE_DISCONTINUITY:
			counts[2]++;
			if (hdr.len < sizeof(t->pkg->discontinuity)) {
				fprintf(stderr, "Short ordered discontinuity record\n");
				return false;
			}
			etrace_process_discontinuity(t);
			break;
		default:
			fprintf(stderr, "Invalid ordered event spool record type %u\n",
				hdr.type);
			return false;
		}
		replayed_bytes += sizeof(hdr) + hdr.len;
		if (replayed_bytes - reported_bytes >= UINT64_C(64) * 1024 * 1024) {
			fprintf(stderr, "Ordered journal replay-progress: bytes=%" PRIu64
				" tb-exec=%" PRIu64 " context-gap=%" PRIu64
				" discontinuity=%" PRIu64 "\n",
				replayed_bytes, counts[0], counts[1], counts[2]);
			reported_bytes = replayed_bytes;
		}
	}
	if (got < 0) {
		fprintf(stderr, "Ordered event spool: %s\n",
			event_journal_error(t->journal));
		return false;
	}
	if (memcmp(counts, t->journal_counts, sizeof(counts))) {
		fprintf(stderr, "Ordered event spool record counts differ\n");
		return false;
	}
	etrace_report_journal(t, "replay-complete");
	fprintf(stderr, "Ordered journal verified sha256=%s\n",
		event_journal_digest(t->journal));
	return true;
}

void etrace_show(int fd, FILE *fp_out,
		 const char *objdump, const char *machine,
		 const char *guest_objdump, const char *guest_machine,
		 void **sym_tree, enum cov_format cov_fmt,
		 enum trace_format trace_in_fmt,
		 enum trace_format trace_out_fmt,
		 const struct address_map *address_map,
		 const struct elf_context *elf_context,
		 bool auto_map, size_t unresolved_limit,
		 bool preserve_order, const char *event_spool,
		 uint64_t event_spool_limit, uint64_t event_spool_decoded_limit)
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
	t.elf_context = elf_context;
	t.auto_map = auto_map;
	t.unresolved_limit = unresolved_limit;
	t.preserve_order = preserve_order;
	if (preserve_order) {
		t.event_spool = event_spool ? fopen(event_spool, "w+b") : tmpfile();
		if (!t.event_spool) {
			fprintf(stderr, "Unable to open ordered event spool: %s\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}
		t.journal = event_journal_new(t.event_spool, event_spool_limit,
					     event_spool_decoded_limit);
	}
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
	t.tb_defs = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL,
					 etrace_tb_definition_free);
	t.contexts = g_hash_table_new_full(g_int64_hash, g_int64_equal,
					free, free);
	t.physical_bindings = g_array_new(false, true,
					 sizeof(struct physical_binding));
	t.binding_buckets = g_hash_table_new_full(g_int64_hash, g_int64_equal,
						free, (GDestroyNotify)g_array_unref);
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
			if (t.preserve_order) {
				if (!etrace_spool_event(&t)) {
					free(t.pkg);
					exit(EXIT_FAILURE);
				}
			} else {
				etrace_process_discontinuity(&t);
			}
			break;
		case TYPE_STATUS:
			etrace_process_status(&t);
			break;
		case TYPE_TB_DEF:
			if (!etrace_process_tb_def(&t, cov_fmt)) {
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
	if (gzclose(t.input) != Z_OK) {
		fprintf(stderr, "Unable to finish ETrace input\n");
		exit(EXIT_FAILURE);
	}
	if (t.elf_context && t.elf_context->configured
	    && (!t.info_seen || !(t.info.attr & ETRACE_INFO_F_CONTEXT))) {
		fprintf(stderr,
			"ELF context matching requires trace context records\n");
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
			" mapping-errors=%" PRIu64
			" code-errors=%" PRIu64 "\n",
			t.status.unresolved_tb_exits,
			t.status.unresolved_discontinuities,
			t.status.unresolved_vcpu_exits,
			t.status.output_errors,
			t.context_errors,
			t.mapping_errors,
			t.code_errors);
		exit(EXIT_FAILURE);
	}
	if (t.preserve_order
	    && !etrace_replay_ordered_events(&t, cov_fmt))
		exit(EXIT_FAILURE);
	if (t.preserve_order && t.final_status_seen)
		etrace_output_status(&t);
	event_journal_free(t.journal);
	if (t.event_spool && fclose(t.event_spool) != 0) {
		fprintf(stderr, "Unable to close ordered event spool: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (t.auto_map && t.unresolved_events) {
		fprintf(stderr,
			"Automatic mapping left %" PRIu64
			" execution events in %zu unresolved aggregates"
			" (%" PRIu64 " ambiguous TBs)\n",
			t.unresolved_events, t.unresolved_entries,
			t.ambiguous_tbs);
	}
	if (t.auto_map && t.resolved_events) {
		fprintf(stderr,
			"Automatic mapping replayed %" PRIu64
			" deferred execution events\n",
			t.resolved_events);
	}
	if (t.auto_map && t.inferred_image_mappings) {
		fprintf(stderr,
			"Automatic mapping established %" PRIu64
			" context-qualified executable image mapping%s\n",
			t.inferred_image_mappings,
			t.inferred_image_mappings == 1 ? "" : "s");
	}
	if (t.auto_map && t.code_candidates) {
		fprintf(stderr,
			"Automatic mapping retained %" PRIu64
			" unverified code-match candidates\n",
			t.code_candidates);
	}
	if (t.preserve_order && t.ordered_unresolved) {
		fprintf(stderr,
			"Ordered replay retained %" PRIu64
			" unresolved execution boundaries\n",
			t.ordered_unresolved);
	}
	g_hash_table_destroy(t.contexts);
	g_hash_table_destroy(t.tb_defs);
	g_array_free(t.physical_bindings, true);
	g_hash_table_destroy(t.binding_buckets);
	free(t.sequence_seen);
	free(t.last_sequence);
	free(t.pkg);
	fprintf(stderr, "done.\n");
}
