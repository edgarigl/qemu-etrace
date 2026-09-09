#include <elf.h>
#include <stdio.h>
#include <string.h>

#include "elf-context.h"
#include "etrace-format.h"

struct context_name {
	const char *architecture;
	const char *level;
	uint16_t machine;
	uint8_t privilege;
};

static const struct context_name context_names[] = {
	{ "aarch64", "el0", EM_AARCH64, 0 },
	{ "aarch64", "el1", EM_AARCH64, 1 },
	{ "aarch64", "el2", EM_AARCH64, 2 },
	{ "aarch64", "el3", EM_AARCH64, 3 },
	{ "i386", "cpl0", EM_386, 0 },
	{ "i386", "cpl1", EM_386, 1 },
	{ "i386", "cpl2", EM_386, 2 },
	{ "i386", "cpl3", EM_386, 3 },
	{ "x86_64", "cpl0", EM_X86_64, 0 },
	{ "x86_64", "cpl1", EM_X86_64, 1 },
	{ "x86_64", "cpl2", EM_X86_64, 2 },
	{ "x86_64", "cpl3", EM_X86_64, 3 },
};

bool elf_context_parse(struct elf_context *context, const char *spec,
		       char *error, size_t error_size)
{
	const char *separator = strchr(spec, ':');
	size_t architecture_len;
	size_t i;

	if (!separator || separator == spec || !separator[1]
	    || strchr(separator + 1, ':')) {
		snprintf(error, error_size, "expected ARCH:LEVEL");
		return false;
	}
	architecture_len = separator - spec;
	for (i = 0; i < sizeof(context_names) / sizeof(context_names[0]); i++) {
		const struct context_name *name = &context_names[i];

		if (strlen(name->architecture) != architecture_len
		    || strncmp(name->architecture, spec, architecture_len)
		    || strcmp(name->level, separator + 1))
			continue;
		*context = (struct elf_context) {
			.configured = true,
			.architecture = name->machine,
			.privilege = name->privilege,
		};
		return true;
	}
	snprintf(error, error_size, "unsupported architecture or privilege level");
	return false;
}

bool elf_context_matches(const struct elf_context *expected,
			 uint16_t architecture, uint8_t privilege,
			 uint32_t flags)
{
	if (!expected || !expected->configured)
		return true;
	return architecture == expected->architecture
		&& (flags & ETRACE_CONTEXT_F_PRIVILEGE_VALID)
		&& privilege == expected->privilege;
}
