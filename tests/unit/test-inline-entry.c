#include <glib.h>
#include <string.h>

#include "inline-entry.h"

static void make_code(uint8_t *code)
{
	const uint8_t prefix[] = {
		0x48, 0x83, 0xb9, 0x98, 0, 0, 0, 0, /* cmpq $0,0x98(%rcx) */
		0x48, 0xf7, 0xd6, /* not %rsi */
	};

	memset(code, 0x90, 0x30);
	memcpy(code, prefix, sizeof(prefix));
	code[11] = 0x74;
	code[12] = 0x13;
	memcpy(code + 0x13, prefix, sizeof(prefix));
	code[0x1e] = 0x75;
	code[0x1f] = 0xed;
}

static bool matches(const uint8_t *code, size_t len, uint64_t base)
{
	struct inline_range ranges[] = {
		{ base, base + 0x10 }, { base + 0x13, base + 0x30 },
	};

	return inline_entry_clone_x86_64(code, len, base, base, base + 0x13,
					ranges, G_N_ELEMENTS(ranges));
}

static void test_conditions(void)
{
	uint8_t code[0x30];
	unsigned int cc;

	make_code(code);
	for (cc = 0; cc < 16; cc++) {
		code[11] = 0x70 | cc;
		code[0x1e] = 0x70 | (cc ^ 1);
		g_assert_true(matches(code, sizeof(code), 0x1000));
		g_assert_true(matches(code, sizeof(code), UINT64_MAX - 0x100));
		g_assert_true(matches(code, sizeof(code), 0));
		code[0x1e] = 0x70 | cc;
		g_assert_false(matches(code, sizeof(code), 0x1000));
	}
}

static void test_prefix_and_successors(void)
{
	uint8_t code[0x30];
	size_t i;

	make_code(code);
	for (i = 0; i < 11; i++) {
		code[0x13 + i] ^= 1;
		g_assert_false(matches(code, sizeof(code), 0x1000));
		code[0x13 + i] ^= 1;
	}
	code[0x1f]++;
	g_assert_false(matches(code, sizeof(code), 0x1000));
	make_code(code);
	code[12]++;
	g_assert_false(matches(code, sizeof(code), 0x1000));
	make_code(code);
	/* Equal PC-relative encodings refer to different data at different PCs. */
	code[2] = code[0x15] = 0x3d;
	g_assert_false(matches(code, sizeof(code), 0x1000));
	make_code(code);
	/* An identical epilogue is not an implementation of an entry comparison. */
	code[0] = code[0x13] = 0x5b;
	g_assert_false(matches(code, sizeof(code), 0x1000));
}

static void test_ranges(void)
{
	uint8_t code[0x30];
	struct inline_range ranges[] = { { 0x1000, 0x1010 }, { 0x1013, 0x1020 } };
	size_t i;

	make_code(code);
	for (i = 0; i < sizeof(code); i++)
		g_assert_false(matches(code, i, 0x1000));
	g_assert_false(inline_entry_clone_x86_64(code, sizeof(code), 0x1000,
		0x1000, 0x1013, ranges, G_N_ELEMENTS(ranges)));
	g_assert_false(matches(code, sizeof(code), UINT64_MAX - 0x20));
}

static void test_external_path(void)
{
	struct inline_range ranges[] = { { 0x1000, 0x1010 }, { 0x1013, 0x1030 } };
	struct inline_instruction insns[] = {
		{ 0xff0, 0xff2, 0x1013, INLINE_FLOW_BRANCH },
		{ 0xff2, 0x1000, 0, INLINE_FLOW_NEXT },
		{ 0x1000, 0x1008, 0, INLINE_FLOW_NEXT },
		{ 0x1008, 0x1013, 0, INLINE_FLOW_NEXT },
		{ 0x1013, 0x1020, 0, INLINE_FLOW_STOP },
	};

	g_assert_true(inline_entry_external_path(insns, G_N_ELEMENTS(insns),
		0x1013, ranges, G_N_ELEMENTS(ranges)));
	/* Reaching the candidate only through the inline body is insufficient. */
	insns[0].kind = INLINE_FLOW_NEXT;
	g_assert_false(inline_entry_external_path(insns, G_N_ELEMENTS(insns),
		0x1013, ranges, G_N_ELEMENTS(ranges)));
	insns[0].kind = INLINE_FLOW_STOP;
	g_assert_false(inline_entry_external_path(insns, G_N_ELEMENTS(insns),
		0x1013, ranges, G_N_ELEMENTS(ranges)));
	insns[0].kind = INLINE_FLOW_JUMP;
	insns[0].target = 0xff0;
	g_assert_false(inline_entry_external_path(insns, G_N_ELEMENTS(insns),
		0x1013, ranges, G_N_ELEMENTS(ranges)));
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/inline-entry/conditions", test_conditions);
	g_test_add_func("/inline-entry/prefix-and-successors", test_prefix_and_successors);
	g_test_add_func("/inline-entry/ranges", test_ranges);
	g_test_add_func("/inline-entry/external-path", test_external_path);
	return g_test_run();
}
