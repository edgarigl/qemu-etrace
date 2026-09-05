#include <glib.h>

#include "dwarf-lines.h"

static void test_normal_row(void)
{
	struct dwarf_line_row row;

	g_assert_true(dwarf_line_parse(
		"0x00401008  [  20, 0] NS DI=0x3 uri: \"source.S\"\n",
		&row));
	g_assert_cmpuint(row.address, ==, 0x401008);
	g_assert_cmpuint(row.line, ==, 20);
	g_assert_cmpuint(row.discriminator, ==, 3);
	g_assert_true(row.is_stmt);
	g_assert_false(row.end_sequence);
	g_assert_cmpstr(row.filename, ==, "source.S");
	dwarf_line_row_clear(&row);
}

static void test_end_sequence_row(void)
{
	struct dwarf_line_row row;

	g_assert_true(dwarf_line_parse(
		"0x00401007  [  12, 0] NS ET\n", &row));
	g_assert_cmpuint(row.address, ==, 0x401007);
	g_assert_cmpuint(row.line, ==, 12);
	g_assert_true(row.is_stmt);
	g_assert_true(row.end_sequence);
	g_assert_null(row.filename);
	dwarf_line_row_clear(&row);
}

static void test_reject_non_row(void)
{
	struct dwarf_line_row row;

	g_assert_false(dwarf_line_parse("Source lines:\n", &row));
	g_assert_false(dwarf_line_parse("0x10 malformed\n", &row));
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/dwarf-lines/normal-row", test_normal_row);
	g_test_add_func("/dwarf-lines/end-sequence-row", test_end_sequence_row);
	g_test_add_func("/dwarf-lines/reject-non-row", test_reject_non_row);
	return g_test_run();
}
