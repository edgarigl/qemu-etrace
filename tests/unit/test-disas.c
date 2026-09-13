#include <glib.h>
#include <stdbool.h>
#include <stdint.h>

#include "disas.h"

struct aarch64_case {
	const char *name;
	uint32_t encoding;
	enum disas_insn_kind kind;
	enum disas_insn_directness directness;
	bool target_valid;
	uint64_t target;
	bool fallthrough_valid;
	bool metadata_only;
};

static const struct aarch64_case cases[] = {
	{
		.name = "b.cond",
		.encoding = UINT32_C(0x54000100), /* b.eq 0x1020 */
		.kind = DISAS_INSN_CONDITIONAL_BRANCH,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0x1020,
		.fallthrough_valid = true,
	},
	{
		.name = "cbz",
		.encoding = UINT32_C(0xb4000100), /* cbz x0, 0x1020 */
		.kind = DISAS_INSN_CONDITIONAL_BRANCH,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0x1020,
		.fallthrough_valid = true,
	},
	{
		.name = "cbnz",
		.encoding = UINT32_C(0x35000101), /* cbnz w1, 0x1020 */
		.kind = DISAS_INSN_CONDITIONAL_BRANCH,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0x1020,
		.fallthrough_valid = true,
	},
	{
		.name = "tbz",
		.encoding = UINT32_C(0x36180102), /* tbz w2, #3, 0x1020 */
		.kind = DISAS_INSN_CONDITIONAL_BRANCH,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0x1020,
		.fallthrough_valid = true,
	},
	{
		.name = "tbnz",
		.encoding = UINT32_C(0x37180102), /* tbnz w2, #3, 0x1020 */
		.kind = DISAS_INSN_CONDITIONAL_BRANCH,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0x1020,
		.fallthrough_valid = true,
	},
	{
		.name = "b",
		.encoding = UINT32_C(0x14000008), /* b 0x1020 */
		.kind = DISAS_INSN_JUMP,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0x1020,
	},
	{
		.name = "bl",
		.encoding = UINT32_C(0x94000008), /* bl 0x1020 */
		.kind = DISAS_INSN_CALL,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0x1020,
	},
	{
		.name = "br",
		.encoding = UINT32_C(0xd61f0060), /* br x3 */
		.kind = DISAS_INSN_JUMP,
		.directness = DISAS_DIRECTNESS_INDIRECT,
	},
	{
		.name = "blr",
		.encoding = UINT32_C(0xd63f0080), /* blr x4 */
		.kind = DISAS_INSN_CALL,
		.directness = DISAS_DIRECTNESS_INDIRECT,
	},
	{
		.name = "ret",
		.encoding = UINT32_C(0xd65f03c0), /* ret */
		.kind = DISAS_INSN_RETURN,
		.directness = DISAS_DIRECTNESS_INDIRECT,
	},
	{
		.name = "svc",
		.encoding = UINT32_C(0xd4000241), /* svc #0x12 */
		.kind = DISAS_INSN_TRAP,
		.directness = DISAS_DIRECTNESS_NONE,
	},
	{
		.name = "brk",
		.encoding = UINT32_C(0xd42000e0), /* brk #7 */
		.kind = DISAS_INSN_TRAP,
		.directness = DISAS_DIRECTNESS_NONE,
	},
	{
		.name = "ordinary",
		.encoding = UINT32_C(0xd503201f), /* nop */
		.kind = DISAS_INSN_ORDINARY,
		.directness = DISAS_DIRECTNESS_NONE,
		.fallthrough_valid = true,
		.metadata_only = true,
	},
	{
		.name = "backward-b.cond",
		.encoding = UINT32_C(0x54ffff80), /* b.eq 0xff0 */
		.kind = DISAS_INSN_CONDITIONAL_BRANCH,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0xff0,
		.fallthrough_valid = true,
	},
	{
		.name = "zero-target",
		.encoding = UINT32_C(0x17fffc00), /* b 0 */
		.kind = DISAS_INSN_JUMP,
		.directness = DISAS_DIRECTNESS_DIRECT,
		.target_valid = true,
		.target = 0,
	},
};

static void encode_le32(uint8_t code[4], uint32_t encoding)
{
	code[0] = encoding;
	code[1] = encoding >> 8;
	code[2] = encoding >> 16;
	code[3] = encoding >> 24;
}

static void test_aarch64_case(gconstpointer user_data)
{
	const struct aarch64_case *test = user_data;
	struct disas_insn result;
	uint8_t code[4];

	encode_le32(code, test->encoding);
	g_assert_true(disas_insn_classify("aarch64", false, 0x1000,
					  code, sizeof(code), &result));
	g_assert_cmpuint(result.size, ==, 4);
	g_assert_cmpint(result.kind, ==, test->kind);
	g_assert_cmpint(result.directness, ==, test->directness);
	g_assert_cmpint(result.confidence, ==, test->metadata_only
			? DISAS_CONFIDENCE_METADATA
			: DISAS_CONFIDENCE_ARCHITECTURE);
	g_assert_cmpint(result.provider, ==, test->metadata_only
			? DISAS_PROVIDER_LIBOPCODES
			: DISAS_PROVIDER_AARCH64);
	g_assert_cmpuint(result.delay_slots, ==, 0);
	g_assert_cmpint(result.target_valid, ==, test->target_valid);
	if (test->target_valid)
		g_assert_cmphex(result.target, ==, test->target);
	g_assert_cmpint(result.fallthrough_valid, ==,
			test->fallthrough_valid);
	if (test->fallthrough_valid)
		g_assert_cmphex(result.fallthrough, ==, 0x1004);
}

static void test_unknown_machine(void)
{
	struct disas_insn result;
	uint8_t code[4] = { 0 };

	g_assert_false(disas_insn_classify("not-a-real-machine", false,
					   0x1000, code, sizeof(code),
					   &result));
}

static void test_x86_fallthrough(void)
{
	static const struct {
		const uint8_t code[9];
		size_t size;
		bool fallthrough;
	} tests[] = {
		{ { 0x90 }, 1, true },
		{ { 0xf0, 0x48, 0x83, 0x05, 0, 0, 0, 0, 1 }, 9, true },
		{ { 0x75, 0 }, 2, true },
		{ { 0xeb, 0 }, 2, false },
		{ { 0xe8, 0, 0, 0, 0 }, 5, false },
		{ { 0xc3 }, 1, false },
	};
	struct disas_insn result;
	size_t i;

	if (!disas_insn_classify("i386:x86-64", false, 0x1000,
				 tests[0].code, tests[0].size, &result)) {
		g_test_skip("x86-64 libopcodes target is unavailable");
		return;
	}
	for (i = 0; i < G_N_ELEMENTS(tests); i++) {
		g_assert_true(disas_insn_classify("i386:x86-64", false, 0x1000,
						  tests[i].code, tests[i].size,
						  &result));
		g_assert_cmpuint(result.size, ==, tests[i].size);
		g_assert_cmpint(result.fallthrough_valid, ==,
				tests[i].fallthrough);
		if (tests[i].fallthrough)
			g_assert_cmphex(result.fallthrough, ==,
					0x1000 + tests[i].size);
	}
}

int main(int argc, char **argv)
{
	size_t i;

	g_test_init(&argc, &argv, NULL);
	for (i = 0; i < G_N_ELEMENTS(cases); i++) {
		char *path = g_strdup_printf("/disas/aarch64/%s", cases[i].name);

		g_test_add_data_func(path, &cases[i], test_aarch64_case);
		g_free(path);
	}
	g_test_add_func("/disas/unknown-machine", test_unknown_machine);
	g_test_add_func("/disas/x86/fallthrough", test_x86_fallthrough);

	return g_test_run();
}
