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
	CACHEGRIND,
	GCOV,
	QCOV,
	LCOV,
};

void coverage_emit(void **store, const char *filename, enum cov_format fmt,
		const char *gcov_strip, const char *gcov_prefix,
		const char *exclude);
void coverage_init(void **store, const char *filename, enum cov_format fmt,
                const char *gcov_strip, const char *gcov_prefix);

#endif
