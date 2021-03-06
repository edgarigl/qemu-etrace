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
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

bool fd_is_socket(int fd)
{
	struct stat statbuf;

	fstat(fd, &statbuf);
	return S_ISSOCK(statbuf.st_mode);
}

bool filename_is_likely_header(const char *s)
{
	unsigned int len;

	if (!s)
		return false;

	len = strlen(s);
	if (len < 3)
		return false;

	if (s[len - 2] == '.'
		&& s[len - 1] == 'h')
		return true;
	return false;
}

void *safe_malloc(size_t size)
{
	void *p = malloc(size);
	if (!p) {
		fprintf(stderr, "malloc(%zd) Out of memory!\n", size);
		exit(1);
	}
	return p;
}

void *safe_mallocz(size_t size)
{
	void *p = calloc(1, size);
	if (!p) {
		fprintf(stderr, "mallocz(%zd) Out of memory!\n", size);
		exit(1);
	}
	return p;
}

void *safe_realloc(void *ptr, size_t size)
{
	void *new;

	new = realloc(ptr, size);
	if (new == NULL && size > 0) {
		fprintf(stderr, "realloc(%zd) Out of memory!\n", size);
		exit(1);
	}
	return new;
}

size_t get_filesize(int fd)
{
	struct stat sbuf;
	int err;

	err = fstat(fd, &sbuf);
	if (err < 0) {
		perror("fstat");
		exit(1);
	}
	return sbuf.st_size;
}
