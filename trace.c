/*
 * Common execution trace processing.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "address-map.h"
#include "syms.h"
#include "trace.h"

void trace_process_exec(struct tracer *tr, enum cov_format cov_fmt,
			const struct trace_exec *exec,
			trace_exec_output_fn output, void *opaque)
{
	uint64_t cursor = exec->start;
	uint64_t accounted = 0;
	uint64_t count = exec->count ? exec->count : 1;
	uint64_t total_len = exec->end >= exec->start
		? exec->end - exec->start : 0;

	while (cursor < exec->end) {
		struct trace_exec_segment out;
		struct address_map_segment segment;
		uint64_t segment_len;

		if (!address_map_next_segment(tr->address_map, &cursor, exec->end,
					      &segment))
			break;

		segment_len = segment.runtime_end - segment.runtime_start;
		out.runtime_start = segment.runtime_start;
		out.runtime_end = segment.runtime_end;
		out.linked_start = segment.linked_start;
		out.linked_end = segment.linked_end;
		out.mapped = segment.mapped;
		out.sym = NULL;
		if (segment.runtime_end == exec->end) {
			out.duration = exec->duration - accounted;
		} else {
			out.duration = total_len
				? (uint64_t)(((__uint128_t)exec->duration * segment_len)
					     / total_len) : 0;
			accounted += out.duration;
		}

		if (tr->sym_tree && *tr->sym_tree)
			out.sym = sym_lookup_by_addr(tr->sym_tree,
						 segment.linked_start);

		if (output)
			output(tr, exec, &out, opaque);

		if (cov_fmt == NONE)
			continue;
		if (tr->sym_tree && *tr->sym_tree)
			sym_update_image_cov(tr->sym_tree, segment.linked_start,
					     segment.linked_end, count);
		if (!out.sym)
			out.sym = sym_get_unknown(tr->sym_tree);

		if (out.sym) {
			uint64_t addr = segment.linked_start;
			struct sym *sym = out.sym;

			while (sym && addr < segment.linked_end) {
				uint64_t end = segment.linked_end;

				if (end > sym->addr + sym->size) {
					end = sym->addr + sym->size;
					fprintf(stderr,
						"WARNING: fixup sym %s has spans over "
						"to another symbol\n", sym->name);
				}
				sym_update_cov(sym, addr, end, out.duration, count);
				addr = end;
				sym = sym_lookup_by_addr(tr->sym_tree, addr);
			}
		}
	}
}
