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

static int fprintf_discard(void *stream, const char *fmt, ...)
{
	(void) stream;
	(void) fmt;
	return 0;
}

static int fprintf_styled_discard(void *stream,
				  enum disassembler_style style,
				  const char *fmt, ...)
{
	(void) stream;
	(void) style;
	(void) fmt;
	return 0;
}

static void set_fallthrough(struct disas_insn *result, uint64_t addr)
{
	if (result->size <= UINT64_MAX - addr) {
		result->fallthrough = addr + result->size;
		result->fallthrough_valid = true;
	}
}

static void classify_libopcode(const struct disassemble_info *inf,
			       uint64_t addr, struct disas_insn *result)
{
	result->provider = DISAS_PROVIDER_LIBOPCODES;
	result->confidence = DISAS_CONFIDENCE_METADATA;
	result->delay_slots = (unsigned char)inf->branch_delay_insns;

	switch (inf->insn_type) {
	case dis_nonbranch:
	case dis_dref:
	case dis_dref2:
		result->kind = DISAS_INSN_ORDINARY;
		result->directness = DISAS_DIRECTNESS_NONE;
		set_fallthrough(result, addr);
		break;
	case dis_branch:
		result->kind = DISAS_INSN_JUMP;
		result->directness = DISAS_DIRECTNESS_UNKNOWN;
		if (inf->target) {
			result->directness = DISAS_DIRECTNESS_DIRECT;
			result->target = inf->target;
			result->target_valid = true;
		}
		break;
	case dis_condbranch:
		result->kind = DISAS_INSN_CONDITIONAL_BRANCH;
		result->directness = DISAS_DIRECTNESS_UNKNOWN;
		if (inf->target) {
			result->directness = DISAS_DIRECTNESS_DIRECT;
			result->target = inf->target;
			result->target_valid = true;
		}
		set_fallthrough(result, addr);
		break;
	case dis_jsr:
		result->kind = DISAS_INSN_CALL;
		result->directness = DISAS_DIRECTNESS_UNKNOWN;
		if (inf->target) {
			result->directness = DISAS_DIRECTNESS_DIRECT;
			result->target = inf->target;
			result->target_valid = true;
		}
		break;
	case dis_condjsr:
		result->kind = DISAS_INSN_CALL;
		result->directness = DISAS_DIRECTNESS_UNKNOWN;
		if (inf->target) {
			result->directness = DISAS_DIRECTNESS_DIRECT;
			result->target = inf->target;
			result->target_valid = true;
		}
		set_fallthrough(result, addr);
		break;
	case dis_noninsn:
	default:
		result->kind = DISAS_INSN_UNKNOWN;
		result->directness = DISAS_DIRECTNESS_UNKNOWN;
		break;
	}
}

static int64_t sign_extend(uint64_t value, unsigned int bits)
{
	uint64_t sign = UINT64_C(1) << (bits - 1);

	return (int64_t)((value ^ sign) - sign);
}

static uint32_t read_aarch64_insn(const uint8_t *buf)
{
	/* AArch64 instruction fetches are little-endian in both data modes. */
	return (uint32_t)buf[0]
		| (uint32_t)buf[1] << 8
		| (uint32_t)buf[2] << 16
		| (uint32_t)buf[3] << 24;
}

static void set_aarch64_kind(struct disas_insn *result,
			     enum disas_insn_kind kind,
			     enum disas_insn_directness directness)
{
	result->kind = kind;
	result->directness = directness;
	result->confidence = DISAS_CONFIDENCE_ARCHITECTURE;
	result->provider = DISAS_PROVIDER_AARCH64;
	result->target = 0;
	result->fallthrough = 0;
	result->target_valid = false;
	result->fallthrough_valid = false;
}

static void set_aarch64_direct(struct disas_insn *result,
			       enum disas_insn_kind kind, uint64_t addr,
			       uint64_t immediate, unsigned int bits)
{
	set_aarch64_kind(result, kind, DISAS_DIRECTNESS_DIRECT);
	result->target = addr + sign_extend(immediate, bits);
	result->target_valid = true;
	if (kind == DISAS_INSN_CONDITIONAL_BRANCH)
		set_fallthrough(result, addr);
}

static void classify_aarch64(uint64_t addr, const uint8_t *buf,
			     struct disas_insn *result)
{
	uint32_t insn = read_aarch64_insn(buf);

	if ((insn & UINT32_C(0xff000000)) == UINT32_C(0x54000000)) {
		set_aarch64_direct(result, DISAS_INSN_CONDITIONAL_BRANCH,
				     addr,
				     (uint64_t)((insn >> 5) & 0x7ffff) << 2,
				     21);
	} else if ((insn & UINT32_C(0x7e000000))
		   == UINT32_C(0x34000000)) {
		set_aarch64_direct(result, DISAS_INSN_CONDITIONAL_BRANCH,
				     addr,
				     (uint64_t)((insn >> 5) & 0x7ffff) << 2,
				     21);
	} else if ((insn & UINT32_C(0x7e000000))
		   == UINT32_C(0x36000000)) {
		set_aarch64_direct(result, DISAS_INSN_CONDITIONAL_BRANCH,
				     addr,
				     (uint64_t)((insn >> 5) & 0x3fff) << 2,
				     16);
	} else if ((insn & UINT32_C(0xfc000000))
		   == UINT32_C(0x14000000)) {
		set_aarch64_direct(result, DISAS_INSN_JUMP, addr,
				     (uint64_t)(insn & 0x3ffffff) << 2, 28);
	} else if ((insn & UINT32_C(0xfc000000))
		   == UINT32_C(0x94000000)) {
		set_aarch64_direct(result, DISAS_INSN_CALL, addr,
				     (uint64_t)(insn & 0x3ffffff) << 2, 28);
	} else if ((insn & UINT32_C(0xfffffc1f))
		   == UINT32_C(0xd61f0000)) {
		set_aarch64_kind(result, DISAS_INSN_JUMP,
				   DISAS_DIRECTNESS_INDIRECT);
	} else if ((insn & UINT32_C(0xfffffc1f))
		   == UINT32_C(0xd63f0000)) {
		set_aarch64_kind(result, DISAS_INSN_CALL,
				   DISAS_DIRECTNESS_INDIRECT);
	} else if ((insn & UINT32_C(0xfffffc1f))
		   == UINT32_C(0xd65f0000)) {
		set_aarch64_kind(result, DISAS_INSN_RETURN,
				   DISAS_DIRECTNESS_INDIRECT);
	} else if ((insn & UINT32_C(0xffff0000)) == 0
		   || (insn & UINT32_C(0xffe0001f))
		      == UINT32_C(0xd4000001)
		   || (insn & UINT32_C(0xffe0001f))
		      == UINT32_C(0xd4000002)
		   || (insn & UINT32_C(0xffe0001f))
		      == UINT32_C(0xd4000003)
		   || (insn & UINT32_C(0xffe0001f))
		      == UINT32_C(0xd4200000)
		   || (insn & UINT32_C(0xffe0001f))
		      == UINT32_C(0xd4400000)
		   || (insn & UINT32_C(0xffe0001f))
		      == UINT32_C(0xd4a00001)
		   || (insn & UINT32_C(0xffe0001f))
		      == UINT32_C(0xd4a00002)
		   || (insn & UINT32_C(0xffe0001f))
		      == UINT32_C(0xd4a00003)) {
		set_aarch64_kind(result, DISAS_INSN_TRAP,
				   DISAS_DIRECTNESS_NONE);
	}
}

bool disas_insn_classify(const char *machine, bool big_endian,
			 uint64_t addr, const void *buf, size_t len,
			 struct disas_insn *result)
{
	const bfd_arch_info_type *arch_inf;
	struct disassemble_info inf;
	disassembler_ftype disas_fn;
	bfd *abfd;
	int size;

	if (!machine || !buf || !len || !result)
		return false;

	memset(result, 0, sizeof(*result));
	result->kind = DISAS_INSN_UNKNOWN;
	result->directness = DISAS_DIRECTNESS_UNKNOWN;

	arch_inf = bfd_scan_arch(machine);
	if (!arch_inf)
		return false;

	abfd = bfd_openr("/dev/null", "binary");
	if (!abfd)
		return false;
	abfd->arch_info = arch_inf;

	init_disassemble_info(&inf, NULL, fprintf_discard,
			      fprintf_styled_discard);
	inf.buffer = (bfd_byte *)buf;
	inf.buffer_vma = addr;
	inf.buffer_length = len;
	inf.endian = big_endian ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
	inf.arch = bfd_get_arch(abfd);
	inf.mach = bfd_get_mach(abfd);
	inf.insn_info_valid = 0;
	inf.insn_type = dis_nonbranch;
	disassemble_init_for_target(&inf);

#ifdef BINUTILS_2_29_OR_NEWER
	disas_fn = disassembler(bfd_get_arch(abfd), big_endian,
				 bfd_get_mach(abfd), abfd);
#else
	disas_fn = disassembler(abfd);
#endif
	if (!disas_fn) {
		bfd_close(abfd);
		return false;
	}

	size = disas_fn(addr, &inf);
	if (size <= 0 || (size_t)size > len) {
		bfd_close(abfd);
		return false;
	}

	result->size = (size_t)size;
	if (inf.insn_info_valid)
		classify_libopcode(&inf, addr, result);
	if (inf.insn_info_valid && bfd_get_arch(abfd) == bfd_arch_aarch64
	    && result->size == 4)
		classify_aarch64(addr, buf, result);

	bfd_close(abfd);
	return true;
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
		fflush(fp_out);
		safe_write(fileno(fp_out), s + pos, fsize - pos);
	}

	munmap(output, fsize_aligned);
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
