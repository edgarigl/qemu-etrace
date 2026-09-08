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
 */

#ifndef ETRACE_H
#define ETRACE_H

#include <stdio.h>

#include "coverage.h"
#include "etrace-format.h"
#include "trace.h"

void etrace_show(int fd, FILE *fp_out,
                 const char *objdump, const char *machine,
                 const char *guest_objdump, const char *guest_machine,
                 void **sym_tree, enum cov_format cov_fmt,
		 enum trace_format trace_in_fmt,
		 enum trace_format trace_out_fmt,
		 const struct address_map *address_map,
		 bool auto_map, size_t unresolved_limit,
		 bool preserve_order, const char *event_spool,
		 uint64_t event_spool_limit, uint64_t event_spool_decoded_limit);

#endif
