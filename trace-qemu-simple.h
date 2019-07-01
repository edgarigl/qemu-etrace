/*
 * This file is part of qemu-etrace.
 *
 * Copyright (c) 2019 Luc Michel <luc.michel@greensocs.com>
 *
 * qemu-etrace is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * qemu-etrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with qemu-etrace.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _TRACE_QEMU_SIMPLE_H
#define _TRACE_QEMU_SIMPLE_H

#include <stdio.h>
#include <stdint.h>

#include "trace.h"
#include "coverage.h"

void qemu_simple_trace_show(int fd, FILE *fp_out,
							const char *objdump, const char *machine,
							const char *guest_objdump, const char *guest_machine,
							void **sym_tree, enum cov_format cov_fmt,
							enum trace_format trace_in_fmt,
							enum trace_format trace_out_fmt);

#endif
