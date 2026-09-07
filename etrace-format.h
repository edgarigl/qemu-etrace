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
 */

#ifndef ETRACE_FORMAT_H
#define ETRACE_FORMAT_H

#include <stdint.h>

enum {
	TYPE_EXEC = 1,
	TYPE_TB = 2,
	TYPE_NOTE = 3,
	TYPE_MEM = 4,
	TYPE_ARCH = 5,
	TYPE_BARRIER = 6,
	TYPE_OLD_EVENT_U64 = 7,
	TYPE_EVENT_U64 = 8,
	TYPE_DISCONTINUITY = 9,
	TYPE_STATUS = 10,
	TYPE_TB_DEF = 11,
	TYPE_TB_EXEC = 12,
	TYPE_CONTEXT = 13,
	TYPE_CONTEXT_GAP = 14,
	TYPE_INFO = 0x4554,
} __attribute__ ((packed));

enum {
	ETRACE_VERSION_LEGACY = 0,
	ETRACE_VERSION_TB_EXEC = 1,
};

struct etrace_hdr {
	uint16_t type;
	union {
		uint16_t unit_id;
	};
	uint32_t len;
} __attribute__ ((packed));

enum etrace_info_flags {
	ETRACE_INFO_F_TB_CHAINING = (1 << 0),
	ETRACE_INFO_F_FINAL_STATUS = (1 << 1),
	ETRACE_INFO_F_TB_EXEC = (1 << 2),
	ETRACE_INFO_F_CONTEXT = (1 << 3),
	ETRACE_INFO_F_FILTERED = (1 << 4),
	ETRACE_INFO_F_EXEC_MAPPING = (1 << 5),
	ETRACE_INFO_F_TB_CODE = (1 << 6),
};

enum etrace_context_flags {
	ETRACE_CONTEXT_F_PRIVILEGE_VALID = (1 << 0),
	ETRACE_CONTEXT_F_ADDRESS_SPACE_VALID = (1 << 1),
	ETRACE_CONTEXT_F_VM_VALID = (1 << 2),
	ETRACE_CONTEXT_F_PAGING = (1 << 3),
	ETRACE_CONTEXT_F_LONG_MODE = (1 << 4),
	ETRACE_CONTEXT_F_VIRTUALIZED = (1 << 5),
	ETRACE_CONTEXT_F_VIRTUALIZATION_ROOT = (1 << 6),
	ETRACE_CONTEXT_F_HYPERVISOR = (1 << 7),
	ETRACE_CONTEXT_F_INCOMPLETE = (1 << 8),
};

struct etrace_info_data {
	uint64_t attr;
	struct {
		uint16_t major;
		uint16_t minor;
	} version;
} __attribute__ ((packed));

struct etrace_arch {
	struct {
		uint32_t arch_id;
		uint8_t arch_bits;
		uint8_t big_endian;
	} guest, host;
} __attribute__ ((packed));

struct etrace_entry32 {
	uint32_t duration;
	uint32_t start, end;
} __attribute__ ((packed));

struct etrace_entry64 {
	uint32_t duration;
	uint64_t start, end;
} __attribute__ ((packed));

struct etrace_exec {
	uint64_t start_time;
	union {
		struct etrace_entry32 t32[0];
		struct etrace_entry64 t64[0];
	};
} __attribute__ ((packed));

struct etrace_note {
	uint64_t time;
	uint8_t data8[0];
} __attribute__ ((packed));

enum etrace_mem_attr {
	MEM_READ = (0 << 0),
	MEM_WRITE = (1 << 0),
};

struct etrace_mem {
	uint64_t time;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t value;
	uint32_t attr;
	uint8_t size;
	uint8_t padd[3];
} __attribute__ ((packed));

struct etrace_tb {
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t host_addr;
	uint32_t guest_code_len;
	uint32_t host_code_len;
	uint8_t data8[0];
} __attribute__ ((packed));

/*
 * Version 1 translation-block definition. Variable data is laid out as
 * insn_count instruction records, mapping_count mapping records, and
 * code_len bytes of guest code.
 */
struct etrace_tb_def {
	uint64_t tb_id;
	uint64_t vaddr;
	uint64_t context_id;
	uint64_t code_hash;
	uint32_t size;
	uint32_t code_len;
	uint16_t insn_count;
	uint16_t mapping_count;
	uint32_t flags;
	uint32_t reserved;
	uint8_t data8[0];
} __attribute__ ((packed));

struct etrace_tb_insn {
	uint32_t offset;
	uint16_t size;
	uint16_t flags;
} __attribute__ ((packed));

struct etrace_tb_mapping {
	uint32_t offset;
	uint32_t len;
	uint64_t paddr;
} __attribute__ ((packed));

struct etrace_tb_exec {
	uint64_t sequence;
	uint64_t time;
	uint64_t tb_id;
	uint64_t context_id;
	uint32_t duration;
	uint16_t insn_count;
	uint16_t flags;
} __attribute__ ((packed));

/*
 * Version 1 execution context. Each register value is encoded as an
 * etrace_context_register followed by name_len name bytes and size value
 * bytes. Names are not NUL terminated and values use target byte order.
 */
struct etrace_context {
	uint64_t context_id;
	uint64_t pc;
	uint64_t address_space_id;
	uint64_t virtual_machine_id;
	uint64_t state_hash;
	uint32_t flags;
	uint16_t architecture;
	uint8_t privilege;
	uint8_t register_count;
	uint32_t reserved;
	uint8_t data8[0];
} __attribute__ ((packed));

struct etrace_context_register {
	uint16_t name_len;
	uint16_t size;
	uint32_t flags;
	uint8_t data8[0];
} __attribute__ ((packed));

enum etrace_context_gap_reason {
	ETRACE_CONTEXT_GAP_FILTERED = 1,
};

struct etrace_context_gap {
	uint64_t sequence;
	uint64_t from_context_id;
	uint64_t to_context_id;
	uint64_t filtered_execs;
	uint32_t reason;
	uint32_t flags;
} __attribute__ ((packed));

struct etrace_old_event_u64 {
	uint64_t time;
	uint64_t val;
	uint16_t unit_id;
	uint16_t dev_name_len;
	uint16_t event_name_len;
	uint8_t names[0];
} __attribute__ ((packed));

struct etrace_event_u64 {
	uint32_t flags;
	uint16_t unit_id;
	uint16_t __reserved;
	uint64_t time;
	uint64_t val;
	uint64_t prev_val;
	uint16_t dev_name_len;
	uint16_t event_name_len;
	uint8_t names[0];
} __attribute__ ((packed));

enum etrace_discontinuity_kind {
	ETRACE_DISCONTINUITY_UNKNOWN,
	ETRACE_DISCONTINUITY_INTERRUPT,
	ETRACE_DISCONTINUITY_EXCEPTION,
	ETRACE_DISCONTINUITY_HOST_CALL,
};

struct etrace_discontinuity {
	uint64_t from_pc;
	uint64_t to_pc;
	uint32_t kind;
	uint32_t flags;
} __attribute__ ((packed));

enum etrace_status_flags {
	ETRACE_STATUS_F_COMPLETE = (1 << 0),
};

struct etrace_status {
	uint64_t unresolved_tb_exits;
	uint64_t unresolved_discontinuities;
	uint64_t unresolved_vcpu_exits;
	uint64_t output_errors;
	uint64_t discontinuity_pc_mismatches;
	uint32_t flags;
	uint32_t reserved;
} __attribute__ ((packed));

struct etrace_status_v1 {
	struct etrace_status base;
	uint64_t filtered_execs;
	uint64_t context_errors;
	uint64_t mapping_errors;
	uint64_t code_errors;
} __attribute__ ((packed));

struct etrace_pkg {
	struct etrace_hdr hdr;
	union {
		struct etrace_info_data info;
		struct etrace_arch arch;
		struct etrace_exec ex;
		struct etrace_tb tb;
		struct etrace_tb_def tb_def;
		struct etrace_tb_exec tb_exec;
		struct etrace_context context;
		struct etrace_context_gap context_gap;
		struct etrace_note note;
		struct etrace_mem mem;
		struct etrace_old_event_u64 old_event_u64;
		struct etrace_event_u64 event_u64;
		struct etrace_discontinuity discontinuity;
		struct etrace_status status;
		uint8_t u8[0];
		uint16_t u16[0];
		uint32_t u32[0];
		uint64_t u64[0];
	};
};

#endif
