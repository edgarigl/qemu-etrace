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
#ifndef _TRACE_H
#define _TRACE_H

#include <stdio.h>
#include <stdint.h>

struct sym;

enum trace_format {
	TRACE_NONE = 0,
	TRACE_ETRACE,
	TRACE_HUMAN,
	TRACE_VCD,
	TRACE_ASCII_HEX,
	TRACE_ASCII_HEX_LE16,
	TRACE_ASCII_HEX_LE32,
	TRACE_ASCII_HEX_LE64,
	TRACE_ASCII_HEX_BE16,
	TRACE_ASCII_HEX_BE32,
	TRACE_ASCII_HEX_BE64
};

struct tracer {
	int fd;
	FILE *fp_out;
	enum trace_format out_fmt;
	void **sym_tree;

	struct {
		const char *objdump;
		const char *machine;
	} host, guest;
};

struct trace_backend {
	void (*exec)(char *unitname, uint64_t start, uint64_t end,
			struct sym *sym);
};

#endif
