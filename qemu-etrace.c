/*
 * QEMU etrace post-processing tool.
 *
 * Copyright: 2013 Xilinx Inc
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "coverage.h"
#include "etrace.h"
#include "util.h"
#include "syms.h"
#include "run.h"
#include <bfd.h>

struct {
	const char *str;
	enum cov_format val;
} covmap[] = {
	{ "none", NONE },
	{ "etrace", ETRACE },
	{ "cachegrind", CACHEGRIND },
	{ "gcov-bad", GCOV },
	{ "qcov", QCOV },
	{ "lcov", LCOV },
	{ NULL, NONE },
};

static inline enum cov_format map_covformat(const char *s)
{
	int i = 0;

	while (covmap[i].str) {
		if (strcmp(covmap[i].str, s) == 0)
			return covmap[i].val;
		i++;
	}
	fprintf(stderr, "Invalid coverage format %s\n", s);
	exit(EXIT_FAILURE);
	return NONE;
}

struct
{
	char *trace_filename;
	char *trace_output;
	char *elf;
	char *addr2line;
	char *nm;
	char *objdump;
	char *guest_objdump;
	char *machine;
	char *guest_machine;
	enum cov_format coverage_format;
	char *coverage_output;
	char *gcov_strip;
	char *gcov_prefix;
} args = {
	.trace_filename = NULL,
	.trace_output = "-",
	.elf = NULL,
	.addr2line = "/usr/bin/addr2line",
	.nm = "/usr/bin/nm",
	.objdump = "/usr/bin/objdump",
	.guest_objdump = "objdump",
	.machine = NULL,
	.guest_machine = NULL,
	.coverage_format = NONE,
	.coverage_output = NULL,
	.gcov_strip = NULL,
	.gcov_prefix = NULL,
};

#define PACKAGE_VERSION "0.1"

static const char etrace_usagestr[] = \
"qemu-etrace " PACKAGE_VERSION "\n"
"-h | --help            Help.\n"
"--trace                Trace filename.\n"
"--trace-output         Decoded trace output filename.\n"
"--elf                  Elf file of traced app.\n"
"--addr2line            Path to addr2line binary.\n"
"--nm                   Path to nm binary.\n"
"--objdump              Path to objdump. \n"
"--machine              Host machine name. See objdump --help.\n"
"--guest-objdump        Path to guest objdump.\n"
"--guest-machine        Guest machine name. See objdump --help.\n"
"--gcov-strip           Strip the specified prefix.\n"
"--gcov-prefix          Prefix with the specified prefix.\n"
"--coverage-format      Kind of coverage.\n"
"--coverage-output      Coverage filename (if applicable).\n"
"\n";

void usage(void)
{
	unsigned int i;
	puts(etrace_usagestr);

	printf("\nSupported coverage formats:\n");
	i = 0;
	while (covmap[i].str) {
		printf("%s%s", i == 0 ? "" : ",", covmap[i].str);
		i++;
	}
	printf("\n");

}

static void parse_arguments(int argc, char **argv)
{
        int c;

	while (1) {
		static struct option long_options[] = {
			{"help",          no_argument, 0, 'h' },
			{"trace",         required_argument, 0, 't' },
			{"trace-output",  required_argument, 0, 'o' },
			{"elf",           required_argument, 0, 'e' },
			{"addr2line",     required_argument, 0, 'a' },
			{"nm",            required_argument, 0, 'n' },
			{"objdump",       required_argument, 0, 'd' },
			{"machine",       required_argument, 0, 'm' },
			{"guest-objdump", required_argument, 0, 'x' },
			{"guest-machine", required_argument, 0, 'g' },
			{"coverage-format", required_argument, 0, 'f' },
			{"coverage-output", required_argument, 0, 'c' },
			{"gcov-strip", required_argument, 0, 'z' },
			{"gcov-prefix", required_argument, 0, 'p' },
			{0,         0,                 0,  0 }
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "bc:t:e:m:g:n:o:x:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
			break;
		case 'c':
			args.coverage_output = optarg;
			break;
		case 'f':
			args.coverage_format = map_covformat(optarg);
			break;
		case 't':
			args.trace_filename = optarg;
			break;
		case 'o':
			args.trace_output = optarg;
			break;
		case 'e':
			args.elf = optarg;
			break;
		case 'a':
			args.addr2line = optarg;
			break;
		case 'n':
			args.nm = optarg;
			break;
		case 'd':
			args.objdump = optarg;
			break;
		case 'x':
			args.guest_objdump = optarg;
			break;
		case 'm':
			args.machine = optarg;
			break;
		case 'g':
			args.guest_machine = optarg;
			break;
		case 'z':
			args.gcov_strip = optarg;
			break;
		case 'p':
			args.gcov_prefix = optarg;
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;
		}
	}
}

FILE *open_trace_output(const char *outname)
{
	char *buf;
	FILE *fp;

	if (!strcmp(outname, "-")) {
		return stdout;
	} else if (!strcmp(outname, "none"))
		return NULL;

	fp = fopen(outname, "w+");
	if (!fp) {
		perror(outname);
		exit(1);
	}

#define BUFSIZE (32 * 1024)
	buf = safe_malloc(BUFSIZE);
	setvbuf(fp, buf, _IOFBF, BUFSIZE);
#undef BUFSIZE

	return fp;
}

void validate_arguments(void)
{
	if (!args.coverage_output
	    && (args.coverage_format != NONE
		&& args.coverage_format != GCOV
		&& args.coverage_format != QCOV)) {
		fprintf(stderr, "A coverage format that needs an output filechosen\n"
			" but no output file!\n"
			"Try using the --coverage-output option.\n\n");
		usage();
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	FILE *trace_out;
	void *sym_tree = NULL;
	int fd;

	bfd_init();

	parse_arguments(argc, argv);
	validate_arguments();

	fd = open(args.trace_filename, O_RDONLY);
	if (fd < 0) {
		perror(args.trace_filename);
		exit(1);
	}

	if (args.elf) {
		sym_read_from_elf(&sym_tree, args.nm, args.elf);
		if (args.coverage_format != NONE)
			sym_build_linemap(&sym_tree, args.addr2line, args.elf);

	}

	coverage_init(&sym_tree, args.coverage_output, args.coverage_format,
		args.gcov_strip, args.gcov_prefix);

	trace_out = open_trace_output(args.trace_output);

	etrace_show(fd, trace_out,
		    args.objdump, args.machine,
		    args.guest_objdump, args.guest_machine,
		    &sym_tree, args.coverage_format);
	sym_show_stats(&sym_tree);


	if (args.coverage_format != NONE)
		coverage_emit(&sym_tree, args.coverage_output,
				args.coverage_format,
				args.gcov_strip, args.gcov_prefix);

	return EXIT_SUCCESS;
}
