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

#define _LARGEFILE64_SOURCE
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

#include "config.h"
#include "util.h"
#include "safeio.h"
#include "disas.h"
#include "run.h"

#include "bfd.h"
#include "dis-asm.h"

/* Print address in hex, truncated to the width of a target virtual address. */
static void
print_address(bfd_vma addr, struct disassemble_info *info)
{
	fprintf(info->stream, "%" PRIx64, (uint64_t) addr);
}

static int
fprintf_styled(void *fp, enum disassembler_style style,
               const char *fmt, ...)
{
  FILE *f = fp;
  va_list ap;
  int r;

  va_start(ap, fmt);
  r = vfprintf(f, fmt, ap);
  va_end(ap);
  return r;
}

bool disas_libopcode(FILE *fp_out, const char *machine, bool big_endian,
		     uint64_t addr, void *buf, size_t len)
{
	bfd *abfd = NULL;
	struct disassemble_info inf;
	const bfd_arch_info_type *arch_inf = bfd_scan_arch (machine);
	disassembler_ftype disas_fn;
	int size, pos;

	if (!arch_inf) {
		return false;
	}

	abfd = bfd_openr("/dev/null", "binary");
	abfd->arch_info = arch_inf;

	init_disassemble_info (&inf, fp_out, (fprintf_ftype) fprintf,
			       fprintf_styled);
	inf.buffer = buf;
	inf.buffer_vma = addr;
	inf.buffer_length = len;
	inf.endian = big_endian ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
	inf.print_address_func = print_address;

	disassemble_init_for_target(&inf);

#ifdef BINUTILS_2_29_OR_NEWER
	disas_fn = disassembler (bfd_get_arch (abfd),
			         bfd_big_endian(abfd),
				 bfd_get_mach(abfd), abfd);
#else
	disas_fn = disassembler (abfd);
#endif
	pos = 0;
	do {
		fprintf(fp_out, "%" PRIx64 "\t", addr + pos);
		size = disas_fn(addr + pos, &inf);
		pos += size;
		fputc('\n', fp_out);
	} while (pos < len);
	bfd_close(abfd);
	return true;
}

void disas_objdump(FILE *fp_out, const char *objdump, const char *machine,
	bool big_endian,
	uint64_t addr, void *buf, size_t len)
{
	char *output;
	char template_in[] = "/tmp/etrace-disas-in-XXXXXX";
	char template_out[] = "/tmp/etrace-disas-out-XXXXXX";
        char *str = NULL;
	long pagesize = sysconf(_SC_PAGE_SIZE);
	int stdio[3] = {0, 1, 2};
	int fd_out, fd_in;
	size_t fsize, fsize_aligned, pos = 0;
	pid_t wpid;
	pid_t kid;

	fd_in = mkstemp(template_in);
	fd_out = mkstemp(template_out);
	if (fd_in < 0 || fd_out < 0) {
		perror("mkstemp");
		exit(1);
	}
	unlink(template_out);

	safe_write(fd_in, buf, len);

	if (asprintf(&str, "--adjust-vma=0x%" PRIx64, addr) < 0) {
		fprintf(stderr, "asprintf failed\n");
		exit(1);
	}

	char *nm_argv[] = { (char *) objdump, "-D", "-b", "binary",
			    "-m", (char *) machine,
			    big_endian ? "-EB" : "-EL",
			    str,
			    template_in, NULL};

	stdio[1] = fd_out;
	kid = run(nm_argv[0], nm_argv, stdio);
	wpid = waitpid(kid, NULL, 0);
	if (wpid != kid) {
		perror("wait");
		exit(1);
	}
	unlink(template_in);

	/* Done, now mmap the file.  */
	fsize = get_filesize(fd_out);
	fsize_aligned = align_pow2(fsize, pagesize);
	output = mmap(NULL, fsize_aligned, PROT_READ, MAP_PRIVATE, fd_out, 0);
	if (output == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	{
		char *s = output;
		int nl;

		for (nl = 0; nl < 7; nl++) {
			while (s[pos++] != '\n')
				;
		}
		fflush(stdout);
		safe_write(1, s + pos, fsize - pos);
	}

	close(fd_in);
	close(fd_out);
	free(str);
}

void disas(FILE *fp_out, const char *objdump, const char *machine,
	bool big_endian,
	uint64_t addr, void *buf, size_t len)
{
	if (machine == NULL)
		return;

	if (disas_libopcode(fp_out, machine, big_endian, addr, buf, len))
		return;

	if (objdump == NULL)
		return;
	disas_objdump(fp_out, objdump, machine, big_endian, addr, buf, len);
}
