/*
 * ASCII hex decoding.
 * Written by Edgar E. Iglesias.
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
#include "trace-hex.h"

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <endian.h>

#ifndef le64toh
#include <byteswap.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#define be16toh(x) __bswap_16(x)
#define be32toh(x) __bswap_32(x)
#define be64toh(x) __bswap_64(x)
#else
#define le16toh(x) __bswap_16(x)
#define le32toh(x) __bswap_32(x)
#define le64toh(x) __bswap_64(x)
#define be16toh(x) (x)
#define be32toh(x) (x)
#define be64toh(x) (x)
#endif
#endif

#define ETRACE_MIN_VERSION_MAJOR 0

#define MAX_PKG (2 * 1024 * 1024)

struct hextracer {
	struct tracer tr;
};

static void ht_process_exec(struct hextracer *t,
			    uint64_t start,
			    uint64_t end,
			    enum cov_format cov_fmt)
{
	struct sym *sym = NULL;
	int64_t now = 0;
	uint32_t duration = 1;

	if (t && t->tr.sym_tree && *t->tr.sym_tree)
		sym = sym_lookup_by_addr(t->tr.sym_tree, start);

	if (t->tr.fp_out) {
		fprintf(t->tr.fp_out,
			"Trace %"PRIx64  " %" PRIx64 " - %" PRIx64 " %s\n",
			now, start, end, sym ? sym->name : "");
	}
	if (cov_fmt != NONE) {
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
		now += duration;
	}
}

void hextrace_show(int fd, FILE *fp_out,
		 const char *objdump, const char *machine,
		 const char *guest_objdump, const char *guest_machine,
		 void **sym_tree, enum cov_format cov_fmt,
		 enum trace_format trace_in_fmt,
		 enum trace_format trace_out_fmt)
{
	struct hextracer t;
	FILE *fp_in;
	char *line = NULL;
	size_t len = 0;
	ssize_t ret;

	fp_in = fdopen(fd, "r");
	if (!fp_in) {
		fprintf(stderr, "Cant open input file\n");
		exit(1);
	}

	fprintf(stderr, "Processing hex trace\n");

	t.tr.fd = fd;
	t.tr.fp_out = fp_out;
	t.tr.sym_tree = sym_tree;
	t.tr.host.objdump = objdump;
	t.tr.host.machine = machine;
	t.tr.guest.objdump = guest_objdump;
	t.tr.guest.machine = guest_machine;

	while ((ret = getline(&line, &len, fp_in)) != -1) {
		uint64_t start;

		start = strtoull(line, NULL, 16);
		switch (trace_in_fmt) {
		case TRACE_ASCII_HEX_LE16:
			start = le16toh(start);
			break;
		case TRACE_ASCII_HEX_LE32:
			start = le32toh(start);
			break;
		case TRACE_ASCII_HEX_LE64:
			start = le64toh(start);
			break;
		case TRACE_ASCII_HEX_BE16:
			start = be16toh(start);
			break;
		case TRACE_ASCII_HEX_BE32:
			start = be32toh(start);
			break;
		case TRACE_ASCII_HEX_BE64:
			start = be64toh(start);
			break;
		case TRACE_ASCII_HEX:
		default:
			break;
		}
		ht_process_exec(&t, start, start + 4, cov_fmt);
	}
	free(line);
	fprintf(stderr, "done.\n");
}
