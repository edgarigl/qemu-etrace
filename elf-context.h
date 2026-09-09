#ifndef ELF_CONTEXT_H
#define ELF_CONTEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct elf_context {
	bool configured;
	uint16_t architecture;
	uint8_t privilege;
};

bool elf_context_parse(struct elf_context *context, const char *spec,
		       char *error, size_t error_size);
bool elf_context_matches(const struct elf_context *expected,
			 uint16_t architecture, uint8_t privilege,
			 uint32_t flags);

#endif
