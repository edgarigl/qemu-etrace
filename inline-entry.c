/* Conservative conditional-entry equivalence. SPDX-License-Identifier: GPL-2.0-only */
#include <string.h>
#include <glib.h>

#include "inline-entry.h"

struct entry_block {
	size_t prefix;
	size_t size;
	unsigned int condition;
	uint64_t taken;
	uint64_t fallthrough;
};

static uint64_t range_end(const struct inline_range *ranges, size_t nr,
			  uint64_t address)
{
	size_t i;

	for (i = 0; i < nr; i++)
		if (address >= ranges[i].start && address < ranges[i].end)
			return ranges[i].end;
	return 0;
}

/*
 * Decode only integer CMP/TEST and register NOT. These operations have no
 * implicit PC dependency. Reject RIP/EIP-relative operands, prefixes with
 * execution semantics, and every unsupported instruction. In particular,
 * an epilogue, NOP sequence, or an arbitrary identical byte prefix is not an
 * entry proof. The first operation must be a comparison.
 */
static size_t comparison_insn(const uint8_t *p, size_t len, bool first)
{
	size_t pos = 0, immediate = 0;
	bool operand16 = false, rex_w = false;
	unsigned int op, modrm, mod, rm, reg;

	if (pos < len && p[pos] == 0x66) {
		operand16 = true;
		pos++;
	}
	if (pos < len && p[pos] >= 0x40 && p[pos] <= 0x4f)
		rex_w = (p[pos++] & 8) != 0;
	if (pos >= len)
		return 0;
	op = p[pos++];
	if (op == 0x3c || op == 0xa8)
		immediate = 1;
	else if (op == 0x3d || op == 0xa9)
		immediate = operand16 && !rex_w ? 2 : 4;
	else {
		if (pos >= len)
			return 0;
		modrm = p[pos++];
		mod = modrm >> 6;
		reg = (modrm >> 3) & 7;
		rm = modrm & 7;
		if (op >= 0x38 && op <= 0x3b) {
			/* CMP r/m,reg or reg,r/m. */
		} else if (op == 0x84 || op == 0x85) {
			/* TEST r/m,reg. */
		} else if ((op == 0x80 || op == 0x81 || op == 0x83) && reg == 7) {
			immediate = op == 0x81 ? (operand16 && !rex_w ? 2 : 4) : 1;
		} else if ((op == 0xf6 || op == 0xf7) && reg == 0) {
			immediate = op == 0xf6 ? 1 : (operand16 && !rex_w ? 2 : 4);
		} else if ((op == 0xf6 || op == 0xf7) && reg == 2
			   && mod == 3 && !first) {
			/* Register NOT preserves the comparison flags. */
		} else {
			return 0;
		}
		if (mod == 0 && rm == 5)
			return 0;
		if (mod != 3 && rm == 4) {
			if (pos >= len)
				return 0;
			if (mod == 0 && (p[pos] & 7) == 5)
				immediate += 4;
			pos++;
		}
		if (mod == 1)
			immediate += 1;
		else if (mod == 2)
			immediate += 4;
	}
	return pos + immediate <= len && pos + immediate <= 15 ? pos + immediate : 0;
}

static bool decode_block(const uint8_t *code, size_t len, uint64_t pc,
			 struct entry_block *block)
{
	size_t pos = 0;
	int64_t displacement = 0;

	/* Bound both work and the amount of code used as an entry proof. */
	while (pos < len && pos < 64) {
		size_t size;

		if (pos && code[pos] >= 0x70 && code[pos] <= 0x7f) {
			if (len - pos < 2)
				return false;
			block->condition = code[pos] & 15;
			displacement = (int8_t)code[pos + 1];
			block->size = pos + 2;
			break;
		}
		if (pos && len - pos >= 2 && code[pos] == 0x0f
		    && code[pos + 1] >= 0x80 && code[pos + 1] <= 0x8f) {
			uint32_t value;

			if (len - pos < 6)
				return false;
			value = (uint32_t)code[pos + 2] | (uint32_t)code[pos + 3] << 8
				| (uint32_t)code[pos + 4] << 16 | (uint32_t)code[pos + 5] << 24;
			block->condition = code[pos + 1] & 15;
			displacement = (int32_t)value;
			block->size = pos + 6;
			break;
		}
		size = comparison_insn(code + pos, len - pos, pos == 0);
		if (!size)
			return false;
		pos += size;
	}
	if (!block->size || block->size > UINT64_MAX - pc)
		return false;
	block->prefix = pos;
	block->fallthrough = pc + block->size;
	if (displacement < 0) {
		if (block->fallthrough < (uint64_t)-displacement)
			return false;
		block->taken = block->fallthrough - (uint64_t)-displacement;
	} else {
		if ((uint64_t)displacement > UINT64_MAX - block->fallthrough)
			return false;
		block->taken = block->fallthrough + displacement;
	}
	return block->taken != block->fallthrough;
}

bool inline_entry_clone_x86_64(const uint8_t *code, size_t len, uint64_t base,
			       uint64_t entry, uint64_t candidate,
			       const struct inline_range *ranges, size_t nr_ranges)
{
	struct entry_block a = { 0 }, b = { 0 };
	uint64_t a_end = range_end(ranges, nr_ranges, entry);
	uint64_t b_end = range_end(ranges, nr_ranges, candidate);

	if (len > UINT64_MAX - base || entry == candidate
	    || entry < base || candidate < base || !a_end || !b_end
	    || a_end > base + len || b_end > base + len)
		return false;
	if (!decode_block(code + entry - base, a_end - entry, entry, &a)
	    || !decode_block(code + candidate - base, b_end - candidate, candidate, &b)
	    || a.prefix != b.prefix
	    || memcmp(code + entry - base, code + candidate - base, a.prefix))
		return false;
	if (!range_end(ranges, nr_ranges, a.taken)
	    || !range_end(ranges, nr_ranges, a.fallthrough)
	    || !range_end(ranges, nr_ranges, b.taken)
	    || !range_end(ranges, nr_ranges, b.fallthrough))
		return false;
	/* Equal conditions preserve successors; inverted conditions swap them. */
	return (a.condition == b.condition && a.taken == b.taken
		&& a.fallthrough == b.fallthrough)
		|| ((a.condition ^ 1) == b.condition && a.taken == b.fallthrough
		    && a.fallthrough == b.taken);
}

static size_t instruction_at(const struct inline_instruction *insns, size_t nr,
			     uint64_t address)
{
	size_t low = 0, high = nr;

	while (low < high) {
		size_t mid = low + (high - low) / 2;

		if (insns[mid].address < address)
			low = mid + 1;
		else
			high = mid;
	}
	return low < nr && insns[low].address == address ? low : nr;
}

bool inline_entry_external_path(const struct inline_instruction *insns, size_t nr,
				uint64_t candidate, const struct inline_range *ranges,
				size_t nr_ranges)
{
	bool *seen;
	size_t *queue;
	size_t head = 0, tail = 0;
	bool found = false;

	if (!nr || instruction_at(insns, nr, candidate) == nr)
		return false;
	seen = g_new0(bool, nr);
	queue = g_new(size_t, nr);
	queue[tail++] = 0;
	seen[0] = true;
	while (head < tail && !found) {
		const struct inline_instruction *insn = &insns[queue[head++]];
		uint64_t targets[2];
		size_t count = 0, i;

		if (range_end(ranges, nr_ranges, insn->address))
			continue;
		if (insn->kind == INLINE_FLOW_NEXT || insn->kind == INLINE_FLOW_BRANCH)
			targets[count++] = insn->next;
		if (insn->kind == INLINE_FLOW_JUMP || insn->kind == INLINE_FLOW_BRANCH)
			targets[count++] = insn->target;
		for (i = 0; i < count; i++) {
			size_t index = instruction_at(insns, nr, targets[i]);

			if (targets[i] == candidate) {
				found = true;
				break;
			}
			if (index != nr && !seen[index]) {
				seen[index] = true;
				queue[tail++] = index;
			}
		}
	}
	g_free(queue);
	g_free(seen);
	return found;
}
