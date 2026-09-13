#include <glib.h>

#include "dwarf-lines.h"

static void test_normal_row(void)
{
	struct dwarf_line_row row;

	g_assert_true(dwarf_line_parse(
		"0x00401008  [  20, 17] NS DI=0x3 uri: \"source.S\"\n",
		&row));
	g_assert_cmpuint(row.address, ==, 0x401008);
	g_assert_cmpuint(row.line, ==, 20);
	g_assert_cmpuint(row.column, ==, 17);
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
	g_assert_cmpuint(row.column, ==, 0);
	g_assert_true(row.is_stmt);
	g_assert_true(row.end_sequence);
	g_assert_null(row.filename);
	dwarf_line_row_clear(&row);
}

static void test_zero_line_end_sequence_row(void)
{
	struct dwarf_line_row row;

	g_assert_true(dwarf_line_parse(
		"0x00401007  [   0, 0] ET\n", &row));
	g_assert_cmpuint(row.line, ==, 0);
	g_assert_true(row.end_sequence);
	dwarf_line_row_clear(&row);
}

static void test_reject_non_row(void)
{
	struct dwarf_line_row row;

	g_assert_false(dwarf_line_parse("Source lines:\n", &row));
	g_assert_false(dwarf_line_parse("0x10 malformed\n", &row));
}

static void test_row_metadata_resets(void)
{
	struct dwarf_line_row row;

	g_assert_true(dwarf_line_parse(
		"0x10 [1, 2] NS DI=7 uri: \"source.c\"", &row));
	dwarf_line_row_clear(&row);
	g_assert_true(dwarf_line_parse("0x11 [ 2 , 0 ]", &row));
	g_assert_cmpuint(row.column, ==, 0);
	g_assert_cmpuint(row.discriminator, ==, 0);
	g_assert_false(row.is_stmt);
	g_assert_null(row.filename);
	dwarf_line_row_clear(&row);
}

static void test_reject_bad_coordinates(void)
{
	const char *rows[] = {
		"0x10 [1]", "0x10 [1,]", "0x10 [1, x]", "0x10 [1, 2x]",
		"0x10 [1, -1]", "0x10 [1, 4294967296]", "0x10 [1, 2",
		"0x10 [-1, 0]", "0x10 [4294967296, 0]", "0x10 [, 0]",
	};
	struct dwarf_line_row row;
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(rows); i++)
		g_assert_false(dwarf_line_parse(rows[i], &row));
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/dwarf-lines/normal-row", test_normal_row);
	g_test_add_func("/dwarf-lines/end-sequence-row", test_end_sequence_row);
	g_test_add_func("/dwarf-lines/zero-line-end-sequence-row",
			test_zero_line_end_sequence_row);
	g_test_add_func("/dwarf-lines/reject-non-row", test_reject_non_row);
	g_test_add_func("/dwarf-lines/row-metadata-resets", test_row_metadata_resets);
	g_test_add_func("/dwarf-lines/reject-bad-coordinates",
			test_reject_bad_coordinates);
	return g_test_run();
}
