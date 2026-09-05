#include <glib.h>
#include <stdint.h>
#include <string.h>

#include "address-map.h"

static void add_map(struct address_map *map, const char *spec)
{
	char error[128];

	g_assert_true(address_map_add_spec(map, spec, error, sizeof(error)));
}

static void test_translate(void)
{
	struct address_map map = { 0 };
	uint64_t linked;

	add_map(&map, "0x1000:0x8000:0x100");
	g_assert_true(address_map_translate(&map, 0x1040, &linked));
	g_assert_cmphex(linked, ==, 0x8040);
	g_assert_false(address_map_translate(&map, 0x1100, &linked));
	g_assert_cmphex(linked, ==, 0x1100);
	address_map_destroy(&map);
}

static void test_multiple_maps_are_sorted(void)
{
	struct address_map map = { 0 };
	uint64_t linked;

	add_map(&map, "3000:a000:100");
	add_map(&map, "1000:8000:100");
	g_assert_true(address_map_translate(&map, 0x1080, &linked));
	g_assert_cmphex(linked, ==, 0x8080);
	g_assert_true(address_map_translate(&map, 0x3040, &linked));
	g_assert_cmphex(linked, ==, 0xa040);
	address_map_destroy(&map);
}

static void test_compatible_overlap(void)
{
	struct address_map map = { 0 };
	char error[128];
	uint64_t linked;

	add_map(&map, "1000:8000:100");
	g_assert_true(address_map_add_spec(&map, "1080:8080:100",
					   error, sizeof(error)));
	g_assert_true(address_map_translate(&map, 0x10c0, &linked));
	g_assert_cmphex(linked, ==, 0x80c0);
	address_map_destroy(&map);
}

static void test_conflicting_overlap(void)
{
	struct address_map map = { 0 };
	char error[128];

	add_map(&map, "1000:8000:100");
	g_assert_false(address_map_add_spec(&map, "1080:9000:100",
					    error, sizeof(error)));
	g_assert_nonnull(strstr(error, "different translation"));
	address_map_destroy(&map);
}

static void test_invalid_maps(void)
{
	struct address_map map = { 0 };
	char error[128];

	g_assert_false(address_map_add_spec(&map, "1000:2000",
					    error, sizeof(error)));
	g_assert_false(address_map_add_spec(&map, "not-hex:2000:100",
					    error, sizeof(error)));
	g_assert_false(address_map_add_spec(&map, "1000:2000:0",
					    error, sizeof(error)));
	g_assert_false(address_map_add_spec(&map, "fffffffffffffff0:2000:20",
					    error, sizeof(error)));
	g_assert_false(address_map_add_spec(&map, "1000:fffffffffffffff0:20",
					    error, sizeof(error)));
	address_map_destroy(&map);
}

static void test_split_range(void)
{
	struct address_map map = { 0 };
	struct address_map_segment segment;
	uint64_t cursor = 0x1000;

	add_map(&map, "1004:2000:4");
	g_assert_true(address_map_next_segment(&map, &cursor, 0x100c, &segment));
	g_assert_false(segment.mapped);
	g_assert_cmphex(segment.runtime_start, ==, 0x1000);
	g_assert_cmphex(segment.runtime_end, ==, 0x1004);
	g_assert_true(address_map_next_segment(&map, &cursor, 0x100c, &segment));
	g_assert_true(segment.mapped);
	g_assert_cmphex(segment.linked_start, ==, 0x2000);
	g_assert_cmphex(segment.linked_end, ==, 0x2004);
	g_assert_true(address_map_next_segment(&map, &cursor, 0x100c, &segment));
	g_assert_false(segment.mapped);
	g_assert_cmphex(segment.runtime_start, ==, 0x1008);
	g_assert_cmphex(segment.runtime_end, ==, 0x100c);
	g_assert_false(address_map_next_segment(&map, &cursor, 0x100c, &segment));
	address_map_destroy(&map);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/address-map/translate", test_translate);
	g_test_add_func("/address-map/multiple", test_multiple_maps_are_sorted);
	g_test_add_func("/address-map/compatible-overlap", test_compatible_overlap);
	g_test_add_func("/address-map/conflicting-overlap", test_conflicting_overlap);
	g_test_add_func("/address-map/invalid", test_invalid_maps);
	g_test_add_func("/address-map/split", test_split_range);

	return g_test_run();
}
