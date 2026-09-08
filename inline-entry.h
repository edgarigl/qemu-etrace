#ifndef INLINE_ENTRY_H
#define INLINE_ENTRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct inline_range {
	uint64_t start;
	uint64_t end;
};

enum inline_flow_kind {
	INLINE_FLOW_NEXT,
	INLINE_FLOW_JUMP,
	INLINE_FLOW_BRANCH,
	INLINE_FLOW_STOP,
};

struct inline_instruction {
	uint64_t address;
	uint64_t next;
	uint64_t target;
	enum inline_flow_kind kind;
};

/* Prove equivalence of duplicated initial integer comparisons and branches. */
bool inline_entry_clone_x86_64(const uint8_t *code, size_t len, uint64_t base,
			       uint64_t entry, uint64_t candidate,
			       const struct inline_range *ranges, size_t nr_ranges);

/* Require a caller-entry path that reaches the candidate from outside the DIE. */
bool inline_entry_external_path(const struct inline_instruction *insns, size_t nr,
				uint64_t candidate, const struct inline_range *ranges,
				size_t nr_ranges);

#endif
