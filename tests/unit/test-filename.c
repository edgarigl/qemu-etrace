#include <glib.h>

#include "filename.h"

static void assert_sanitized(const char *input, const char *expected)
{
	char *actual = filename_sanitize(input);

	g_assert_cmpstr(actual, ==, expected);
	g_free(actual);
}

static void test_unchanged(void)
{
	assert_sanitized("src/main.c", "src/main.c");
}

static void test_relative_parent(void)
{
	assert_sanitized("src/lib/../main.c", "src/main.c");
}

static void test_absolute_parent(void)
{
	assert_sanitized("/src/lib/../main.c", "/src/main.c");
}

static void test_parent_at_start(void)
{
	assert_sanitized("/../main.c", "main.c");
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/filename/unchanged", test_unchanged);
	g_test_add_func("/filename/relative-parent", test_relative_parent);
	g_test_add_func("/filename/absolute-parent", test_absolute_parent);
	g_test_add_func("/filename/parent-at-start", test_parent_at_start);

	return g_test_run();
}
