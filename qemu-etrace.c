
/*
 * QEMU etrace post-processing tool.
 *
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
#include <errno.h>
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

#include "config.h"
#include "address-map.h"
#include "elf-context.h"
#include "trace-open.h"
#include "coverage.h"
#include "syms.h"
#include "trace.h"
#include "etrace.h"
#include "trace-hex.h"
#include "util.h"
#include "run.h"
#include <bfd.h>
#include "trace-qemu-simple.h"

struct format_map {
	const char *str;
	int val;
};

struct format_map cov_fmt_map[] = {
	{ "none", NONE },
	{ "etrace", ETRACE },
	{ "etrace-v2", ETRACE_V2 },
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
	{ "qemu-simple", TRACE_QEMU_SIMPLE },
	{ NULL, TRACE_NONE },
};

struct
{
	char *trace_filename;
	char *trace_output;
	char *elf;
	char *exclude;
	char *addr2line;
	char *dwarfdump;
	char *nm;
	char *objdump;
	char *guest_objdump;
	char *machine;
	char *guest_machine;
	enum trace_format trace_in_format;
	enum trace_format trace_out_format;
	enum cov_format coverage_format;
	enum function_hit_policy function_hit_policy;
	enum line_hit_policy line_hit_policy;
	struct address_map address_map;
	struct elf_context elf_context;
	bool auto_map;
	size_t unresolved_limit;
	bool preserve_order;
	char *event_spool;
	uint64_t event_spool_limit;
	uint64_t event_spool_decoded_limit;
	bool server;
	char *coverage_output;
	char *coverage_inventory;
	char *coverage_attribution;
	char *gcov_strip;
	char *gcov_prefix;
} args = {
	.trace_filename = NULL,
	.trace_output = "-",
	.trace_in_format = TRACE_ETRACE,
	.trace_out_format = TRACE_HUMAN,
	.elf = NULL,
	.exclude = NULL,
	.addr2line = "addr2line",
	.dwarfdump = "dwarfdump",
	.nm = "nm",
	.objdump = "objdump",
	.guest_objdump = "objdump",
	.machine = NULL,
	.guest_machine = NULL,
	.coverage_format = NONE,
	.function_hit_policy = FUNCTION_HIT_ENTRY,
	.line_hit_policy = LINE_HIT_ADDRESS,
	.coverage_output = NULL,
	.coverage_inventory = NULL,
	.gcov_strip = NULL,
	.gcov_prefix = NULL,
	.server = true,
	.unresolved_limit = 65536,
	.event_spool_limit = UINT64_C(1) << 30,
	.event_spool_decoded_limit = UINT64_MAX,
};

static const char etrace_usagestr[] = \
"qemu-etrace " PACKAGE_VERSION "\n"
"-h | --help            Help.\n"
"--trace                Trace filename.\n"
"--trace-in-format      Trace input format .\n"
"--trace-out-format     Trace output format .\n"
"--trace-output         Decoded trace output filename.\n"
"--elf                  Elf file of traced app.\n"
"--exclude              Excludes description file.\n"
"--addr2line            Path to addr2line binary.\n"
"--dwarfdump            Path to dwarfdump binary.\n"
"--nm                   Path to nm binary.\n"
"--objdump              Path to objdump. \n"
"--machine              Host machine name. See objdump --help.\n"
"--guest-objdump        Path to guest objdump.\n"
"--guest-machine        Guest machine name. See objdump --help.\n"
"--gcov-strip           Strip the specified prefix.\n"
"--gcov-prefix          Prefix with the specified prefix.\n"
"--coverage-format      Kind of coverage.\n"
"--coverage-output      Coverage filename (if applicable).\n"
"--coverage-inventory   Write a JSON Lines function inventory.\n"
"--coverage-attribution Write JSON Lines DWARF ranges and address counts.\n"
"--function-hit-policy Function hits: entry or source.\n"
"--line-hit-policy     Line hits: address or function-entry.\n"
"--address-map          Map runtime addresses to linked ELF addresses.\n"
"--elf-context          Expected ELF execution context, such as aarch64:el2.\n"
"--auto-map             Infer runtime addresses from TB mappings and code.\n"
"--unresolved-limit     Maximum unresolved TB execution aggregates.\n"
"--preserve-order       Replay auto-mapped events in original order.\n"
"--event-spool          Ordered-event journal path (temporary by default).\n"
"--event-spool-limit    Maximum ordered-event journal size in bytes.\n"
"--event-spool-decoded-limit Maximum decoded journal bytes (default: unlimited).\n"
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
	printf("\n\n");
	printf("The exclude fileformat is a list of filenames:line-numbers.\n"
		"One per line. For example:\n"
		"filename1.c:22\n"
		"filename2.c:38\n\n");
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

static enum function_hit_policy map_function_hit_policy(const char *s)
{
	if (!strcmp(s, "entry"))
		return FUNCTION_HIT_ENTRY;
	if (!strcmp(s, "source"))
		return FUNCTION_HIT_SOURCE;
	fprintf(stderr, "Invalid function hit policy %s\n", s);
	exit(EXIT_FAILURE);
}

static enum line_hit_policy map_line_hit_policy(const char *s)
{
	if (!strcmp(s, "address"))
		return LINE_HIT_ADDRESS;
	if (!strcmp(s, "function-entry"))
		return LINE_HIT_FUNCTION_ENTRY;
	fprintf(stderr, "Invalid line hit policy %s\n", s);
	exit(EXIT_FAILURE);
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
			{"exclude",       required_argument, 0, 'l' },
			{"addr2line",     required_argument, 0, 'a' },
			{"dwarfdump",     required_argument, 0, 'w' },
			{"nm",            required_argument, 0, 'n' },
			{"objdump",       required_argument, 0, 'd' },
			{"machine",       required_argument, 0, 'm' },
			{"guest-objdump", required_argument, 0, 'x' },
			{"guest-machine", required_argument, 0, 'g' },
			{"coverage-format", required_argument, 0, 'f' },
			{"coverage-output", required_argument, 0, 'c' },
			{"coverage-inventory", required_argument, 0, 'I' },
			{"coverage-attribution", required_argument, 0, 1008 },
			{"function-hit-policy", required_argument, 0, 'F' },
			{"line-hit-policy", required_argument, 0, 1007 },
			{"address-map", required_argument, 0, 'A' },
			{"auto-map", no_argument, 0, 1000 },
			{"unresolved-limit", required_argument, 0, 1001 },
			{"preserve-order", no_argument, 0, 1002 },
			{"event-spool", required_argument, 0, 1003 },
			{"event-spool-limit", required_argument, 0, 1004 },
			{"event-spool-decoded-limit", required_argument, 0, 1005 },
			{"elf-context", required_argument, 0, 1006 },
			{"gcov-strip", required_argument, 0, 'z' },
			{"gcov-prefix", required_argument, 0, 'p' },
			{0,         0,                 0,  0 }
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "bc:t:e:m:g:n:o:x:s:l:w:F:A:I:",
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
		case 'I':
			args.coverage_inventory = optarg;
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
		case 'l':
			args.exclude = optarg;
			break;
		case 'a':
			args.addr2line = optarg;
			break;
		case 'w':
			args.dwarfdump = optarg;
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
		case 'F':
			args.function_hit_policy = map_function_hit_policy(optarg);
			break;
		case 'A':
		{
			char error[128];

			if (!address_map_add_spec(&args.address_map, optarg,
						  error, sizeof(error))) {
				fprintf(stderr, "Invalid address map '%s': %s\n",
					optarg, error);
				exit(EXIT_FAILURE);
			}
			break;
		}
		case 1000:
			args.auto_map = true;
			break;
		case 1001:
		{
			char *end;
			unsigned long long limit;

			errno = 0;
			limit = strtoull(optarg, &end, 0);
			if (errno || end == optarg || *end || !limit
			    || limit > SIZE_MAX) {
				fprintf(stderr, "Invalid unresolved limit %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			args.unresolved_limit = limit;
			break;
		}
		case 1002:
			args.preserve_order = true;
			break;
		case 1003:
			args.event_spool = optarg;
			break;
		case 1004:
		case 1005:
		{
			char *end;
			unsigned long long limit;

			errno = 0;
			limit = strtoull(optarg, &end, 0);
			if (errno || end == optarg || *end || !limit
			    || optarg[0] < '0' || optarg[0] > '9') {
				fprintf(stderr, "Invalid event spool %slimit %s\n",
					c == 1005 ? "decoded " : "", optarg);
				exit(EXIT_FAILURE);
			}
			if (c == 1005)
				args.event_spool_decoded_limit = limit;
			else
				args.event_spool_limit = limit;
			break;
		}
		case 1006:
		{
			char error[128];

			if (!elf_context_parse(&args.elf_context, optarg,
					       error, sizeof(error))) {
				fprintf(stderr, "Invalid ELF context '%s': %s\n",
					optarg, error);
				exit(EXIT_FAILURE);
			}
			break;
		}
		case 1007:
			args.line_hit_policy = map_line_hit_policy(optarg);
			break;
		case 1008:
			args.coverage_attribution = optarg;
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
	if (args.function_hit_policy == FUNCTION_HIT_SOURCE
	    && (!args.elf || args.coverage_format != LCOV)) {
		fprintf(stderr, "Source function hits require --elf and "
			"--coverage-format lcov\n");
		exit(EXIT_FAILURE);
	}
	if (args.line_hit_policy == LINE_HIT_FUNCTION_ENTRY
	    && (!args.elf || args.coverage_format != LCOV)) {
		fprintf(stderr, "Function-entry line hits require --elf and "
			"--coverage-format lcov\n");
		exit(EXIT_FAILURE);
	}
	if (args.coverage_inventory
	    && (!args.elf || args.coverage_format != LCOV)) {
		fprintf(stderr, "Coverage inventory requires --elf and "
			"--coverage-format lcov\n");
		exit(EXIT_FAILURE);
	}
	if (args.coverage_attribution
	    && (!args.elf || args.coverage_format != LCOV)) {
		fprintf(stderr, "Coverage attribution requires --elf and "
			"--coverage-format lcov\n");
		exit(EXIT_FAILURE);
	}
	if (args.address_map.count && !args.elf) {
		fprintf(stderr, "Address maps require --elf\n");
		exit(EXIT_FAILURE);
	}
	if (args.elf_context.configured
	    && (!args.elf || args.trace_in_format != TRACE_ETRACE)) {
		fprintf(stderr, "An ELF context requires an ELF and ETrace input\n");
		exit(EXIT_FAILURE);
	}
	if (args.auto_map
	    && (!args.elf || args.trace_in_format != TRACE_ETRACE)) {
		fprintf(stderr, "Automatic mapping requires an ELF and ETrace input\n");
		exit(EXIT_FAILURE);
	}
	if (args.preserve_order && !args.auto_map) {
		fprintf(stderr, "Order preservation requires automatic mapping\n");
		exit(EXIT_FAILURE);
	}
	if (args.event_spool && !args.preserve_order) {
		fprintf(stderr, "An event spool requires --preserve-order\n");
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
		 enum trace_format trace_out_fmt,
		 const struct address_map *address_map,
		 const struct elf_context *elf_context,
		 bool auto_map, size_t unresolved_limit,
		 bool preserve_order, const char *event_spool,
		 uint64_t event_spool_limit, uint64_t event_spool_decoded_limit)
{
	switch (trace_in_fmt) {
	case TRACE_ETRACE:
		etrace_show(fd, fp_out,
			    objdump, machine,
			    guest_objdump, guest_machine,
			    sym_tree, cov_fmt,
			    trace_in_fmt, trace_out_fmt, address_map,
			    elf_context,
			    auto_map, unresolved_limit, preserve_order,
			    event_spool, event_spool_limit, event_spool_decoded_limit);
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
			    trace_in_fmt, trace_out_fmt, address_map);
		break;
	case TRACE_QEMU_SIMPLE:
		qemu_simple_trace_show(fd, fp_out,
			    objdump, machine,
			    guest_objdump, guest_machine,
			    sym_tree, cov_fmt,
			    trace_in_fmt, trace_out_fmt, address_map);
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
	bool is_socket;
	int fd;

	bfd_init();

	parse_arguments(argc, argv);
	validate_arguments();

	if (args.elf) {
		sym_read_from_elf(&sym_tree, args.nm, args.elf);
		if (args.elf_context.configured
		    && args.elf_context.architecture
			!= sym_get_elf_machine(&sym_tree)) {
			fprintf(stderr,
				"ELF context architecture does not match the ELF\n");
			exit(EXIT_FAILURE);
		}
		if (args.coverage_format != NONE)
			sym_build_linemap(&sym_tree, args.dwarfdump, args.elf);
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
		is_socket = fd_is_socket(fd);
		if (is_socket) {
			block_sigint_exit = true;
		}

		trace_show(fd, trace_out,
			   args.objdump, args.machine,
			   args.guest_objdump, args.guest_machine,
			   &sym_tree, args.coverage_format,
			   args.trace_in_format,
			   args.trace_out_format,
			   &args.address_map,
			   &args.elf_context,
			   args.auto_map, args.unresolved_limit,
			   args.preserve_order, args.event_spool,
			   args.event_spool_limit, args.event_spool_decoded_limit);
		close(fd);
	} while (is_socket && !got_sigint && args.server);

	sym_show_stats(&sym_tree);

	if (args.function_hit_policy == FUNCTION_HIT_SOURCE)
		sym_build_source_coverage(&sym_tree, args.addr2line,
					  args.dwarfdump, args.objdump, args.elf);

	if (args.coverage_format != NONE)
		coverage_emit(&sym_tree, args.coverage_output,
				args.coverage_format,
				args.gcov_strip, args.gcov_prefix,
				args.exclude, args.function_hit_policy,
				args.line_hit_policy,
				args.coverage_inventory,
				args.coverage_attribution);
	address_map_destroy(&args.address_map);

	return EXIT_SUCCESS;
}
