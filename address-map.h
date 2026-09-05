#ifndef ADDRESS_MAP_H
#define ADDRESS_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct address_map_entry {
	uint64_t runtime_start;
	uint64_t linked_start;
	uint64_t size;
};

struct address_map {
	struct address_map_entry *entries;
	size_t count;
};

struct address_map_segment {
	uint64_t runtime_start;
	uint64_t runtime_end;
	uint64_t linked_start;
	uint64_t linked_end;
	bool mapped;
};

bool address_map_add(struct address_map *map, uint64_t runtime_start,
		     uint64_t linked_start, uint64_t size,
		     char *error, size_t error_size);
bool address_map_add_spec(struct address_map *map, const char *spec,
			  char *error, size_t error_size);
bool address_map_translate(const struct address_map *map, uint64_t runtime,
			   uint64_t *linked);
bool address_map_next_segment(const struct address_map *map, uint64_t *cursor,
			      uint64_t end,
			      struct address_map_segment *segment);
void address_map_destroy(struct address_map *map);

#endif
