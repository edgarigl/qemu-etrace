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
#include <signal.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "trace-open.h"
#include "coverage.h"
#include "syms.h"
#include "trace.h"
#include "etrace.h"
#include "trace-hex.h"
#include "util.h"
#include "run.h"
#include <bfd.h>

struct format_map {
	const char *str;
	int val;
};

struct format_map cov_fmt_map[] = {
	{ "none", NONE },
	{ "etrace", ETRACE },
	{ "cachegrind", CACHEGRIND },
	{ "gcov-bad", GCOV },
	{ "qcov", QCOV },
	{ "lcov", LCOV },
	{ NULL, NONE },
};

struct format_map trace_fmt_map[] = {
	{ "none", TRACE_NONE },
	{ "etrace", TRACE_ETRACE },
	{ "human", TRACE_HUMAN },
	{ "vcd", TRACE_VCD },
	{ "ascii-hex", TRACE_ASCII_HEX },
	{ "ascii-hex-le16", TRACE_ASCII_HEX_LE16 },
	{ "ascii-hex-le32", TRACE_ASCII_HEX_LE32 },
	{ "ascii-hex-le64", TRACE_ASCII_HEX_LE64 },
	{ "ascii-hex-be16", TRACE_ASCII_HEX_BE16 },
	{ "ascii-hex-be32", TRACE_ASCII_HEX_BE32 },
	{ "ascii-hex-be64", TRACE_ASCII_HEX_BE64 },
	{ NULL, TRACE_NONE },
};

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
	enum trace_format trace_in_format;
	enum trace_format trace_out_format;
	enum cov_format coverage_format;
	bool server;
	char *coverage_output;
	char *gcov_strip;
	char *gcov_prefix;
} args = {
	.trace_filename = NULL,
	.trace_output = "-",
	.trace_in_format = TRACE_ETRACE,
	.trace_out_format = TRACE_HUMAN,
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
	.server = true,
};

#define PACKAGE_VERSION "0.1"

static const char etrace_usagestr[] = \
"qemu-etrace " PACKAGE_VERSION "\n"
"-h | --help            Help.\n"
"--trace                Trace filename.\n"
"--trace-in-format      Trace input format .\n"
"--trace-out-format     Trace output format .\n"
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

	printf("\nSupported trace formats:\n");
	i = 0;
	while (trace_fmt_map[i].str) {
		printf("%s%s", i == 0 ? "" : ",", trace_fmt_map[i].str);
		i++;
	}
	printf("\n");

	printf("\nSupported coverage formats:\n");
	i = 0;
	while (cov_fmt_map[i].str) {
		printf("%s%s", i == 0 ? "" : ",", cov_fmt_map[i].str);
		i++;
	}
	printf("\n");

}

int map_format(struct format_map *map, const char *s)
{
	int i = 0;

	while (map[i].str) {
		if (strcmp(map[i].str, s) == 0)
			return map[i].val;
		i++;
	}
	fprintf(stderr, "Invalid coverage format %s\n", s);
	usage();
	exit(EXIT_FAILURE);

}

static inline enum cov_format map_covformat(const char *s)
{
	return map_format(cov_fmt_map, s);
}

static inline enum trace_format map_traceformat(const char *s)
{
	return map_format(trace_fmt_map, s);
}

static void parse_arguments(int argc, char **argv)
{
        int c;

	while (1) {
		static struct option long_options[] = {
			{"help",          no_argument, 0, 'h' },
			{"server",         required_argument, 0, 's' },
			{"trace",         required_argument, 0, 't' },
			{"trace-in-format",  required_argument, 0, 'y' },
			{"trace-out-format",  required_argument, 0, 'q' },
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

		c = getopt_long(argc, argv, "bc:t:e:m:g:n:o:x:s:",
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
		case 's':
			args.server = strtol(optarg, NULL, 0);
			break;
		case 'z':
			args.gcov_strip = optarg;
			break;
		case 'p':
			args.gcov_prefix = optarg;
			break;
		case 'y':
			args.trace_in_format = map_traceformat(optarg);
			break;
		case 'q':
			args.trace_out_format = map_traceformat(optarg);
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
	int fd;
	FILE *fp;


	/* None is special for output. If you want a file name none,
	   just use ./none as the name.  */
	if (!strcmp(outname, "none"))
		return NULL;

	fd = trace_open(outname, true);
	if (fd < 0) {
		perror(outname);
		exit(1);
	}
	fp = fdopen(fd, "w");
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
	if (!args.trace_filename) {
		fprintf(stderr, "No tracefile selected (--trace)\n");
		exit(EXIT_FAILURE);
	}
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

sig_atomic_t got_sigint = false;
sig_atomic_t block_sigint_exit = false;

void sigint_handler(int s) {
	got_sigint = true;

	if (!block_sigint_exit) {
		exit(EXIT_SUCCESS);
	}
}

void trace_show(int fd, FILE *fp_out,
                 const char *objdump, const char *machine,
                 const char *guest_objdump, const char *guest_machine,
                 void **sym_tree, enum cov_format cov_fmt,
                 enum trace_format trace_in_fmt,
                 enum trace_format trace_out_fmt)
{
	switch (trace_in_fmt) {
	case TRACE_ETRACE:
		etrace_show(fd, fp_out,
			    objdump, machine,
			    guest_objdump, guest_machine,
			    sym_tree, cov_fmt,
			    trace_in_fmt, trace_out_fmt);
		break;
	case TRACE_ASCII_HEX:
	case TRACE_ASCII_HEX_LE16:
	case TRACE_ASCII_HEX_LE32:
	case TRACE_ASCII_HEX_LE64:
	case TRACE_ASCII_HEX_BE16:
	case TRACE_ASCII_HEX_BE32:
	case TRACE_ASCII_HEX_BE64:
		hextrace_show(fd, fp_out,
			    objdump, machine,
			    guest_objdump, guest_machine,
			    sym_tree, cov_fmt,
			    trace_in_fmt, trace_out_fmt);
		break;
	default:
		fprintf(stderr, "Unsupported trace format\n");
		usage();
		exit(1);
		break;
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

	if (args.elf) {
		sym_read_from_elf(&sym_tree, args.nm, args.elf);
		if (args.coverage_format != NONE)
			sym_build_linemap(&sym_tree, args.addr2line, args.elf);

	}

	coverage_init(&sym_tree, args.coverage_output, args.coverage_format,
		args.gcov_strip, args.gcov_prefix);

	trace_out = open_trace_output(args.trace_output);


	{
		struct sigaction shandler;

		shandler.sa_handler = sigint_handler;
		sigemptyset(&shandler.sa_mask);
		shandler.sa_flags = 0;

		sigaction(SIGINT, &shandler, NULL);
	}

	do {
		fd = trace_open(args.trace_filename, false);
		if (fd < 0) {
			perror(args.trace_filename);
			if (block_sigint_exit) {
				break;
			}
			exit(EXIT_FAILURE);
		}
		/* If we are dealing with sockets, we want to handle
		 * SIGINT synchronously with a post process of the
		 * stats prior to exit().
		 */
		if (fd >=0 && fd_is_socket(fd)) {
			block_sigint_exit = true;
		}

		trace_show(fd, trace_out,
			   args.objdump, args.machine,
			   args.guest_objdump, args.guest_machine,
			   &sym_tree, args.coverage_format,
			   args.trace_in_format,
			   args.trace_out_format);
	} while (fd_is_socket(fd) && !got_sigint && args.server);

	sym_show_stats(&sym_tree);

	if (args.coverage_format != NONE)
		coverage_emit(&sym_tree, args.coverage_output,
				args.coverage_format,
				args.gcov_strip, args.gcov_prefix);

	return EXIT_SUCCESS;
}
