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

#include "excludes.h"

struct exclude
{
	struct exclude *next;
        char filename[PATH_MAX];
        unsigned int linenr;
};

void *excludes_create(const char *filename)
{
	struct exclude *ex_root = NULL;
	char *lineptr = NULL;
	size_t n = 0;
	FILE *fp;

	if (!filename)
		return NULL;
	printf("%s: %s\n", __func__, filename);

	fp = fopen(filename, "r");
	if (!fp) {
		perror(filename);
		return NULL;
	}

	while (1) {
		struct exclude *ex;
		ssize_t r;
		char *delim;
		char *t;
		size_t filename_len;

		r = getline(&lineptr, &n, fp);
		if (r <= 0)
			break;

		/* Ignore empty lines and comments.  */
		if (lineptr[0] == '\n' || lineptr[0] == '#')
			continue;

		delim = strchr(lineptr, ':');
		if (!delim) {
			printf("WARNING: Bad exclude line, "
				"missing ':' delimiter\n%s\n", lineptr);
			continue;
		}
		filename_len = delim - lineptr;
		if (filename_len >= sizeof(ex->filename)) {
			printf("WARNING: Exclude filename is too long\n");
			continue;
		}
		ex = malloc(sizeof *ex);
		ex->next = ex_root;
		ex_root = ex;

		t = mempcpy(ex->filename, lineptr, filename_len);
		t[0] = 0;

		delim++;
		ex->linenr = strtoull(delim, NULL, 10);
		printf("Add Exclude %s : %d\n", ex->filename, ex->linenr);
	}

	free(lineptr);
	fclose(fp);
	return ex_root;
}

bool excludes_match(void *excludes, const char *filename, int linenr)
{
	struct exclude *ex = excludes;

	while (ex) {
		if (strcmp(filename, ex->filename) == 0
			&& (linenr == -1 || linenr == ex->linenr)) {
			return true;
		}
		ex = ex->next;
	}
	return false;
}

void excludes_destroy(void *excludes)
{
	struct exclude *ex = excludes;

	while (ex) {
		struct exclude *next = ex->next;

		free(ex);
		ex = next;
	}
}
