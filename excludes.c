/*
 * Copyright: 2013 Xilinx Inc
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
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
	char *lineptr;
	size_t n;
	FILE *fp;

	printf("%s: %s\n", __func__, filename);
	if (!filename)
		return NULL;

	fp = fopen(filename, "r");
	if (!fp) {
		perror(filename);
		return NULL;
	}

	do {
		struct exclude *ex;
		ssize_t r;
		char *delim;
		char *t;

		n = 0;
		lineptr = NULL;

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
		ex = malloc(sizeof *ex);
		ex->next = ex_root;
		ex_root = ex;

		t = mempcpy(ex->filename, lineptr, delim - lineptr);
		t[0] = 0;

		delim++;
		ex->linenr = strtoull(delim, NULL, 10);
		printf("Add Exclude %s : %d\n", ex->filename, ex->linenr);
	} while (1);

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
