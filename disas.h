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

#ifndef QEMU_ETRACE_DISAS_H
#define QEMU_ETRACE_DISAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum disas_insn_kind {
	DISAS_INSN_UNKNOWN,
	DISAS_INSN_ORDINARY,
	DISAS_INSN_CONDITIONAL_BRANCH,
	DISAS_INSN_JUMP,
	DISAS_INSN_CALL,
	DISAS_INSN_RETURN,
	DISAS_INSN_TRAP,
};

enum disas_insn_directness {
	DISAS_DIRECTNESS_NONE,
	DISAS_DIRECTNESS_DIRECT,
	DISAS_DIRECTNESS_INDIRECT,
	DISAS_DIRECTNESS_UNKNOWN,
};

enum disas_insn_confidence {
	DISAS_CONFIDENCE_NONE,
	DISAS_CONFIDENCE_METADATA,
	DISAS_CONFIDENCE_ARCHITECTURE,
};

enum disas_insn_provider {
	DISAS_PROVIDER_NONE,
	DISAS_PROVIDER_LIBOPCODES,
	DISAS_PROVIDER_AARCH64,
};

struct disas_insn {
	size_t size;
	enum disas_insn_kind kind;
	enum disas_insn_directness directness;
	enum disas_insn_confidence confidence;
	enum disas_insn_provider provider;
	uint64_t target;
	uint64_t fallthrough;
	unsigned int delay_slots;
	bool target_valid;
	bool fallthrough_valid;
};

/* A successful decode may still return DISAS_INSN_UNKNOWN. */
bool disas_insn_classify(const char *machine, bool big_endian,
			 uint64_t addr, const void *buf, size_t len,
			 struct disas_insn *result);

void disas(FILE *fp_out, const char *objdump, const char *machine,
	   bool big_endian, uint64_t addr, void *buf, size_t len);

#endif
