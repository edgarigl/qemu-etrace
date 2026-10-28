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
#ifndef _COVERAGE_H
#define _COVERAGE_H

enum cov_format {
	NONE = 0,
	ETRACE,
	ETRACE_V2,
	CACHEGRIND,
	GCOV,
	QCOV,
	LCOV,
};

enum function_hit_policy {
	FUNCTION_HIT_ENTRY = 0,
	FUNCTION_HIT_SOURCE,
};

enum line_hit_policy {
	LINE_HIT_ADDRESS = 0,
	LINE_HIT_FUNCTION_ENTRY,
};

void coverage_emit(void **store, const char *filename, enum cov_format fmt,
			const char *gcov_strip, const char *gcov_prefix,
			const char *exclude, enum function_hit_policy function_policy,
			enum line_hit_policy line_policy,
			const char *inventory_filename,
			const char *attribution_filename);
void coverage_init(void **store, const char *filename, enum cov_format fmt,
                const char *gcov_strip, const char *gcov_prefix);

#endif
