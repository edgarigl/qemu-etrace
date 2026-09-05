#ifndef DWARF_LINES_H
#define DWARF_LINES_H

#include <stdbool.h>
#include <stdint.h>

struct dwarf_line_row {
	uint64_t address;
	unsigned int line;
	unsigned int discriminator;
	bool is_stmt;
	bool end_sequence;
	char *filename;
};

bool dwarf_line_parse(const char *text, struct dwarf_line_row *row);
void dwarf_line_row_clear(struct dwarf_line_row *row);

#endif
