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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <search.h>

#include "util.h"
#include "syms.h"
#include "coverage.h"
#include "cov-cachegrind.h"

static void coverage_dump_sym(struct sym *s, FILE *fp)
{
	fprintf(fp, "fn=%s\n%u %" PRIu64 "\n",
		s->name ? s->name : "unknown",
		0 /*dummy*/, s->total_time);
}

void cachegrind_coverage_dump(struct sym *s, size_t nr_syms,
			      struct sym *unknown, FILE *fp)
{
	size_t i;

	fprintf(fp, "cmd: qemu\n");
	fprintf(fp, "events: time-ns\n");
	fprintf(fp, "fl=???\n");

	for (i = 0; i < nr_syms; i++) {
		coverage_dump_sym(&s[i], fp);
	}
	coverage_dump_sym(unknown, fp);
}
