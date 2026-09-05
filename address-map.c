#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address-map.h"

static bool fail(char *error, size_t error_size, const char *message)
{
	if (error_size)
		snprintf(error, error_size, "%s", message);
	return false;
}

static bool parse_hex(const char *text, uint64_t *value)
{
	char *end;

	if (!text[0] || isspace((unsigned char)text[0])
	    || text[0] == '-' || text[0] == '+')
		return false;
	errno = 0;
	*value = strtoull(text, &end, 16);
	return !errno && end != text && !*end;
}

static uint64_t map_address(const struct address_map_entry *entry,
			    uint64_t runtime)
{
	return entry->linked_start + runtime - entry->runtime_start;
}

bool address_map_add(struct address_map *map, uint64_t runtime_start,
		     uint64_t linked_start, uint64_t size,
		     char *error, size_t error_size)
{
	struct address_map_entry entry = {
		.runtime_start = runtime_start,
		.linked_start = linked_start,
		.size = size,
	};
	uint64_t runtime_end;
	size_t pos;

	if (!size)
		return fail(error, error_size, "address-map size is zero");
	if (size > UINT64_MAX - runtime_start)
		return fail(error, error_size, "runtime address range overflows");
	if (size > UINT64_MAX - linked_start)
		return fail(error, error_size, "linked address range overflows");
	runtime_end = runtime_start + size;

	for (pos = 0; pos < map->count; pos++) {
		const struct address_map_entry *other = &map->entries[pos];
		uint64_t other_end = other->runtime_start + other->size;
		uint64_t overlap;

		if (runtime_start >= other_end || other->runtime_start >= runtime_end)
			continue;
		overlap = runtime_start > other->runtime_start
			? runtime_start : other->runtime_start;
		if (map_address(&entry, overlap) != map_address(other, overlap))
			return fail(error, error_size,
				"address-map overlaps with a different translation");
	}

	struct address_map_entry *entries = realloc(
		map->entries, sizeof(map->entries[0]) * (map->count + 1));
	if (!entries)
		return fail(error, error_size, "unable to allocate address-map");
	map->entries = entries;

	for (pos = map->count; pos > 0; pos--) {
		if (map->entries[pos - 1].runtime_start <= runtime_start)
			break;
		map->entries[pos] = map->entries[pos - 1];
	}
	map->entries[pos] = entry;
	map->count++;
	return true;
}

bool address_map_add_spec(struct address_map *map, const char *spec,
			  char *error, size_t error_size)
{
	uint64_t runtime_start;
	uint64_t linked_start;
	uint64_t size;
	char *copy = strdup(spec);
	char *first;
	char *second;
	bool result;

	if (!copy)
		return fail(error, error_size, "unable to allocate address-map");
	first = strchr(copy, ':');
	second = first ? strchr(first + 1, ':') : NULL;
	if (!first || !second || strchr(second + 1, ':')) {
		free(copy);
		return fail(error, error_size,
			"expected RUNTIME_START:LINKED_START:SIZE");
	}
	*first = '\0';
	*second = '\0';
	result = parse_hex(copy, &runtime_start)
		&& parse_hex(first + 1, &linked_start)
		&& parse_hex(second + 1, &size);
	free(copy);
	if (!result)
		return fail(error, error_size, "address-map values must be hexadecimal");
	return address_map_add(map, runtime_start, linked_start, size,
			       error, error_size);
}

bool address_map_translate(const struct address_map *map, uint64_t runtime,
			   uint64_t *linked)
{
	size_t i;

	for (i = 0; map && i < map->count; i++) {
		const struct address_map_entry *entry = &map->entries[i];

		if (runtime < entry->runtime_start)
			break;
		if (runtime - entry->runtime_start < entry->size) {
			*linked = map_address(entry, runtime);
			return true;
		}
	}
	*linked = runtime;
	return false;
}

bool address_map_next_segment(const struct address_map *map, uint64_t *cursor,
			      uint64_t end,
			      struct address_map_segment *segment)
{
	const struct address_map_entry *entry = NULL;
	uint64_t segment_end = end;
	size_t i;

	if (*cursor >= end)
		return false;

	for (i = 0; map && i < map->count; i++) {
		uint64_t entry_end = map->entries[i].runtime_start
			+ map->entries[i].size;

		if (*cursor >= map->entries[i].runtime_start && *cursor < entry_end) {
			entry = &map->entries[i];
			if (entry_end < segment_end)
				segment_end = entry_end;
			break;
		}
		if (map->entries[i].runtime_start > *cursor
		    && map->entries[i].runtime_start < segment_end)
			segment_end = map->entries[i].runtime_start;
	}

	segment->runtime_start = *cursor;
	segment->runtime_end = segment_end;
	segment->mapped = entry != NULL;
	if (entry) {
		segment->linked_start = map_address(entry, *cursor);
		segment->linked_end = map_address(entry, segment_end);
	} else {
		segment->linked_start = *cursor;
		segment->linked_end = segment_end;
	}
	*cursor = segment_end;
	return true;
}

void address_map_destroy(struct address_map *map)
{
	free(map->entries);
	map->entries = NULL;
	map->count = 0;
}
