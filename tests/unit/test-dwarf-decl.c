#define _GNU_SOURCE
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "dwarf-decl.h"

static const char info[] =
"COMPILE_UNIT<header overall offset = 0x00000000>:\n"
"< 0><0x0000000c GOFF=0x0000000c> DW_TAG_compile_unit\n"
" DW_AT_name src/one.c\n"
" DW_AT_comp_dir /build\n"
"< 1><0x00000020 GOFF=0x00000020> DW_TAG_subprogram\n"
" DW_AT_specification <0x00000080 GOFF=0x00000080>\n"
" DW_AT_low_pc 0x00001000\n"
"< 1><0x00000040 GOFF=0x00000040> DW_TAG_subprogram\n"
" DW_AT_abstract_origin <0x000000a0 GOFF=0x000000a0>\n"
" DW_AT_low_pc 0x00001100\n"
"< 1><0x00000060 GOFF=0x00000060> DW_TAG_variable\n"
" DW_AT_decl_file 0x00000002 /build/include/shared.h\n"
"< 1><0x00000080 GOFF=0x00000080> DW_TAG_subprogram\n"
" DW_AT_name specified\n"
" DW_AT_decl_file 0x00000002\n"
" DW_AT_decl_line 0x00000021\n"
"< 1><0x000000a0 GOFF=0x000000a0> DW_TAG_subprogram\n"
" DW_AT_name abstracted\n"
" DW_AT_decl_file 0x00000001\n"
" DW_AT_decl_line 0x00000007\n"
"< 1><0x000000c0 GOFF=0x000000c0> DW_TAG_subprogram\n"
" DW_AT_linkage_name linked_name\n"
" DW_AT_name source_name\n"
" DW_AT_decl_file 0x00000001\n"
" DW_AT_decl_line 0x00000009\n"
" DW_AT_low_pc 0x00001200\n"
"< 1><0x000000e0 GOFF=0x000000e0> DW_TAG_subprogram\n"
" DW_AT_name ranged\n"
" DW_AT_decl_file 0x00000001\n"
" DW_AT_decl_line 0x0000000c\n"
" DW_AT_low_pc (addr_index: 0x00000000)0x00000000\n"
" DW_AT_ranges 0x00000010\n"
" [ 0] start,end 0x00001400 0x00001410\n"
" [ 1] range entry 0x00001500 0x00001510\n"
" [ 2] end-of-list\n"
"COMPILE_UNIT<header overall offset = 0x00000100>:\n"
"< 0><0x0000000c GOFF=0x0000010c> DW_TAG_compile_unit\n"
" DW_AT_name src/two.c\n"
" DW_AT_comp_dir /other\n"
"< 1><0x00000020 GOFF=0x00000120> DW_TAG_subprogram\n"
" DW_AT_name second_cu\n"
" DW_AT_decl_file 0x00000001\n"
" DW_AT_decl_line 0x0000000b\n"
" DW_AT_low_pc 0x00001300\n";

static void test_declarations(void)
{
	struct dwarf_declarations decls;
	FILE *fp = fmemopen((void *)info, strlen(info), "r");

	g_assert_nonnull(fp);
	g_assert_true(dwarf_declarations_parse(fp, &decls));
	fclose(fp);
	g_assert_cmpuint(decls.count, ==, 7);

	g_assert_cmphex(decls.entries[0].address, ==, 0x1000);
	g_assert_cmpstr(decls.entries[0].name, ==, "specified");
	g_assert_cmpstr(decls.entries[0].filename, ==,
			"/build/include/shared.h");
	g_assert_cmpuint(decls.entries[0].line, ==, 33);

	g_assert_cmphex(decls.entries[1].address, ==, 0x1100);
	g_assert_cmpstr(decls.entries[1].name, ==, "abstracted");
	g_assert_cmpstr(decls.entries[1].filename, ==, "/build/src/one.c");
	g_assert_cmpuint(decls.entries[1].line, ==, 7);

	g_assert_cmphex(decls.entries[2].address, ==, 0x1200);
	g_assert_cmpstr(decls.entries[2].name, ==, "linked_name");
	g_assert_cmpstr(decls.entries[2].filename, ==, "/build/src/one.c");
	g_assert_cmpuint(decls.entries[2].line, ==, 9);

	g_assert_cmphex(decls.entries[3].address, ==, 0);
	g_assert_cmpstr(decls.entries[3].name, ==, "ranged");
	g_assert_cmpuint(decls.entries[3].line, ==, 12);
	g_assert_cmphex(decls.entries[4].address, ==, 0x1400);
	g_assert_cmpstr(decls.entries[4].name, ==, "ranged");
	g_assert_cmpuint(decls.entries[4].line, ==, 12);
	g_assert_cmphex(decls.entries[5].address, ==, 0x1500);
	g_assert_cmpstr(decls.entries[5].name, ==, "ranged");
	g_assert_cmpuint(decls.entries[5].line, ==, 12);

	g_assert_cmphex(decls.entries[6].address, ==, 0x1300);
	g_assert_cmpstr(decls.entries[6].name, ==, "second_cu");
	g_assert_cmpstr(decls.entries[6].filename, ==, "/other/src/two.c");
	g_assert_cmpuint(decls.entries[6].line, ==, 11);

	dwarf_declarations_destroy(&decls);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/dwarf-decl/declarations", test_declarations);
	return g_test_run();
}
