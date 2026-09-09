#include <elf.h>
#include <glib.h>
#include <string.h>

#include "elf-context.h"
#include "etrace-format.h"

static void test_parse(void)
{
	struct elf_context context = { 0 };
	char error[128];

	g_assert_true(elf_context_parse(&context, "aarch64:el2",
					error, sizeof(error)));
	g_assert_true(context.configured);
	g_assert_cmpuint(context.architecture, ==, EM_AARCH64);
	g_assert_cmpuint(context.privilege, ==, 2);

	g_assert_true(elf_context_parse(&context, "x86_64:cpl0",
					error, sizeof(error)));
	g_assert_cmpuint(context.architecture, ==, EM_X86_64);
	g_assert_cmpuint(context.privilege, ==, 0);
}

static void test_invalid(void)
{
	const char *specs[] = {
		"", "aarch64", "aarch64:", ":el2", "aarch64:el4",
		"x86_64:el2", "armv8:el2", "aarch64:el2:extra",
	};
	struct elf_context context = { 0 };
	char error[128];
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(specs); i++)
		g_assert_false(elf_context_parse(&context, specs[i],
						 error, sizeof(error)));
}

static void test_match(void)
{
	struct elf_context context = {
		.configured = true,
		.architecture = EM_AARCH64,
		.privilege = 2,
	};

	g_assert_true(elf_context_matches(&context, EM_AARCH64, 2,
				ETRACE_CONTEXT_F_PRIVILEGE_VALID));
	g_assert_false(elf_context_matches(&context, EM_AARCH64, 1,
				 ETRACE_CONTEXT_F_PRIVILEGE_VALID));
	g_assert_false(elf_context_matches(&context, EM_X86_64, 2,
				 ETRACE_CONTEXT_F_PRIVILEGE_VALID));
	g_assert_false(elf_context_matches(&context, EM_AARCH64, 2, 0));
	g_assert_true(elf_context_matches(NULL, EM_AARCH64, 1, 0));
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/elf-context/parse", test_parse);
	g_test_add_func("/elf-context/invalid", test_invalid);
	g_test_add_func("/elf-context/match", test_match);
	return g_test_run();
}
