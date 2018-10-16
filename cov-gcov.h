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

#define GCOV_DATA_MAGIC ((gcov_unsigned_t)0x67636461) /* "gcda" */
#define GCOV_NOTE_MAGIC ((gcov_unsigned_t)0x67636e6f) /* "gcno" */

#define GCOV_COUNTERS_SUMMABLE  1  /* Counters which can be
                                      summaried.  */
#define GCOV_FIRST_VALUE_COUNTER 1 /* The first of counters used for value
                                      profiling.  They must form a consecutive
                                      interval and their order must match
                                      the order of HIST_TYPEs in
                                      value-prof.h.  */
#define GCOV_COUNTER_V_INTERVAL 1  /* Histogram of value inside an interval.  */
#define GCOV_COUNTER_V_POW2     2  /* Histogram of exact power2 logarithm
                                      of a value.  */
#define GCOV_COUNTER_V_SINGLE   3  /* The most common value of expression.  */
#define GCOV_COUNTER_V_DELTA    4  /* The most common difference between
                                      consecutive values of expression.  */

#define GCOV_COUNTER_V_INDIR    5  /* The most common indirect address */
#define GCOV_COUNTER_AVERAGE    6  /* Compute average value passed to the
                                      counter.  */
#define GCOV_COUNTER_IOR        7  /* IOR of the all values passed to
                                      counter.  */
#define GCOV_LAST_VALUE_COUNTER 7  /* The last of counters used for value
                                      profiling.  */
#define GCOV_COUNTERS           8

/* Arc flags.  */
#define GCOV_ARC_ON_TREE        (1 << 0)
#define GCOV_ARC_FAKE           (1 << 1)
#define GCOV_ARC_FALLTHROUGH    (1 << 2)

typedef uint32_t gcov_unsigned_t;

#define GCOV_TAG_FUNCTION        ((gcov_unsigned_t)0x01000000)
#define GCOV_TAG_FUNCTION_LENGTH (2)
#define GCOV_TAG_BLOCKS          ((gcov_unsigned_t)0x01410000)
#define GCOV_TAG_BLOCKS_LENGTH(NUM) (NUM)
#define GCOV_TAG_BLOCKS_NUM(LENGTH) (LENGTH)
#define GCOV_TAG_ARCS            ((gcov_unsigned_t)0x01430000)
#define GCOV_TAG_ARCS_LENGTH(NUM)  (1 + (NUM) * 2)
#define GCOV_TAG_ARCS_NUM(LENGTH)  (((LENGTH) - 1) / 2)
#define GCOV_TAG_LINES           ((gcov_unsigned_t)0x01450000)
#define GCOV_TAG_COUNTER_BASE    ((gcov_unsigned_t)0x01a10000)
#define GCOV_TAG_COUNTER_LENGTH(NUM) ((NUM) * 2)
#define GCOV_TAG_COUNTER_NUM(LENGTH) ((LENGTH) / 2)
#define GCOV_TAG_OBJECT_SUMMARY  ((gcov_unsigned_t)0xa1000000)
#define GCOV_TAG_PROGRAM_SUMMARY ((gcov_unsigned_t)0xa3000000)

struct gcov_file_header
{
	uint32_t magic;
	uint32_t version;
	uint32_t stamp;
} __attribute__ ((packed));

struct gcov_record_header
{
	uint32_t tag;
	uint32_t length;
} __attribute__ ((packed));

struct gcov_arc {
	uint32_t dest_block;
	uint32_t flags;
} __attribute__ ((packed));

#define MAX_ARCS_PER_BLOCK 1024
struct gcov_arcs {
	uint32_t block_no;
	unsigned int nr_arcs;
	struct gcov_arc arcs[MAX_ARCS_PER_BLOCK];
};

#define MAX_LINES_PER_BLOCK 1024
struct gcov_lines {
	uint32_t block_no;
	unsigned int nr_lines;
	struct {
		uint32_t lineno;
		char *filename;
	} lines[MAX_LINES_PER_BLOCK];
};

struct gcov_counts {
	unsigned int nr_counts;
	uint64_t *counts;
};

struct gcov_blocks {
	int nr_blocks;
	uint32_t *flags;
};

struct gcov_function {
	uint32_t ident;
	uint32_t csum;
	uint32_t cfg_csum;
	char *name;
	char *source;
	uint32_t lineno;
};

struct gcov_count_summary {
	uint32_t num;
	uint32_t runs;
	uint64_t sum;
	uint64_t max;
	uint64_t sum_max;
} __attribute__ ((packed));

struct gcov_summary {
	uint32_t checksum;
	struct gcov_count_summary count_summary[GCOV_COUNTERS_SUMMABLE];
} __attribute__ ((packed));

struct gcov_record
{
	struct gcov_record_header hdr;
	union {
		uint8_t u8[0];
		uint16_t u16[0];
		uint32_t u32[0];
		uint64_t u64[0];
	} data;
} __attribute__ ((packed));

struct gcov_record_ir
{
	struct gcov_function func;

	struct gcov_blocks blocks;

	unsigned int nr_arcs;
	struct gcov_arcs *arcs;

	unsigned int nr_lines;
	struct gcov_lines *lines;

	struct gcov_counts counts;
	struct {
		struct gcov_summary object;
		struct gcov_summary program;;
	} summary;
	struct gcov_record rec;
};

void gcov_emit_gcov(void **store, struct sym *s, size_t nr_syms,
                struct sym *unknown, FILE *fp,
		const char *gcov_strip, const char *gcov_prefix,
		enum cov_format fmt, void *exclude);
