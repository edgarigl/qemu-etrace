#ifndef DWARF_DECL_H
#define DWARF_DECL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct dwarf_decl {
	uint64_t address;
	char *name;
	char *filename;
	unsigned int line;
};

struct dwarf_declarations {
	struct dwarf_decl *entries;
	size_t count;
};

bool dwarf_declarations_parse(FILE *fp, struct dwarf_declarations *decls);
void dwarf_declarations_destroy(struct dwarf_declarations *decls);

#endif
