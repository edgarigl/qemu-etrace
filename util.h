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

void *safe_malloc(size_t size);
void *safe_mallocz(size_t size);
void *safe_realloc(void *ptr, size_t size);
size_t get_filesize(int fd);
static inline size_t align_pow2(size_t v, size_t alignment)
{
	v += alignment - 1;
	v &= ~(alignment - 1);
	return v;
}

bool fd_is_socket(int fd);

bool filename_is_likely_header(const char *s);
