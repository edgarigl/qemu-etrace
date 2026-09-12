#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "dwarf-decl.h"

struct dwarf_decl_file {
	unsigned int index;
	char *name;
};

struct dwarf_decl_cu {
	char *name;
	char *comp_dir;
	struct dwarf_decl_file *files;
	size_t nr_files;
};

struct dwarf_decl_die {
	uint64_t offset;
	uint64_t address;
	uint64_t abstract_origin;
	uint64_t specification;
	char *name;
	char *linkage_name;
	unsigned int file;
	unsigned int line;
	size_t cu;
	bool have_address;
	bool have_abstract_origin;
	bool have_specification;
	bool have_file;
	bool have_line;
};

struct dwarf_decl_parse {
	struct dwarf_decl_cu *cus;
	size_t nr_cus;
	struct dwarf_decl_die *dies;
	size_t nr_dies;
};

static char *copy_value(const char *line, const char *attribute)
{
	const char *value = strstr(line, attribute);
	const char *end;
	size_t len;
	char *copy;

	if (!value)
		return NULL;
	value += strlen(attribute);
	while (isspace((unsigned char)*value))
		value++;
	end = value + strlen(value);
	while (end > value && isspace((unsigned char)end[-1]))
		end--;
	if (end == value)
		return NULL;
	len = end - value;
	copy = malloc(len + 1);
	if (!copy)
		return NULL;
	memcpy(copy, value, len);
	copy[len] = '\0';
	return copy;
}

static bool parse_hex_after(const char *line, const char *marker,
			    uint64_t *value, const char **endp)
{
	const char *start = strstr(line, marker);
	char *end;

	if (!start)
		return false;
	start += strlen(marker);
	errno = 0;
	*value = strtoull(start, &end, 16);
	if (errno || end == start)
		return false;
	if (endp)
		*endp = end;
	return true;
}

static bool parse_attribute_hex(const char *line, const char *attribute,
				uint64_t *value, const char **endp)
{
	const char *start = strstr(line, attribute);
	char *end;

	if (!start)
		return false;
	start += strlen(attribute);
	while (isspace((unsigned char)*start))
		start++;
	errno = 0;
	*value = strtoull(start, &end, 0);
	if (errno || end == start)
		return false;
	if (endp)
		*endp = end;
	return true;
}

static char *copy_trimmed(const char *value)
{
	const char *end = value + strlen(value);
	size_t len;
	char *copy;

	while (end > value && isspace((unsigned char)end[-1]))
		end--;
	if (end == value)
		return NULL;
	len = end - value;
	copy = malloc(len + 1);
	if (!copy)
		return NULL;
	memcpy(copy, value, len);
	copy[len] = '\0';
	return copy;
}

static bool remember_file(struct dwarf_decl_cu *cu, unsigned int index,
			  const char *name)
{
	struct dwarf_decl_file *new_files;
	char *copy;
	size_t i;

	if (!index || !name || !*name)
		return true;
	for (i = 0; i < cu->nr_files; i++) {
		if (cu->files[i].index != index)
			continue;
		return true;
	}
	copy = copy_trimmed(name);
	if (!copy)
		return false;
	new_files = realloc(cu->files,
		(cu->nr_files + 1) * sizeof(*cu->files));
	if (!new_files) {
		free(copy);
		return false;
	}
	cu->files = new_files;
	cu->files[cu->nr_files].index = index;
	cu->files[cu->nr_files].name = copy;
	cu->nr_files++;
	return true;
}

static const char *find_file(const struct dwarf_decl_cu *cu,
			     unsigned int index)
{
	size_t i;

	for (i = 0; i < cu->nr_files; i++)
		if (cu->files[i].index == index)
			return cu->files[i].name;
	return NULL;
}

static bool complete_cu_files(struct dwarf_decl_parse *parse)
{
	size_t i;

	for (i = 0; i < parse->nr_cus; i++) {
		struct dwarf_decl_cu *cu = &parse->cus[i];
		char *path;
		size_t len;

		if (find_file(cu, 1) || !cu->name)
			continue;
		if (cu->name[0] == '/' || !cu->comp_dir) {
			if (!remember_file(cu, 1, cu->name))
				return false;
			continue;
		}
		len = strlen(cu->comp_dir) + strlen(cu->name) + 2;
		path = malloc(len);
		if (!path)
			return false;
		snprintf(path, len, "%s/%s", cu->comp_dir, cu->name);
		if (!remember_file(cu, 1, path)) {
			free(path);
			return false;
		}
		free(path);
	}
	return true;
}

static int die_compare(const void *a, const void *b)
{
	const struct dwarf_decl_die *da = a;
	const struct dwarf_decl_die *db = b;

	return da->offset < db->offset ? -1 : da->offset > db->offset;
}

static const struct dwarf_decl_die *find_die(
	const struct dwarf_decl_parse *parse, uint64_t offset)
{
	size_t low = 0, high = parse->nr_dies;

	while (low < high) {
		size_t mid = low + (high - low) / 2;

		if (parse->dies[mid].offset < offset)
			low = mid + 1;
		else
			high = mid;
	}
	return low < parse->nr_dies && parse->dies[low].offset == offset
		? &parse->dies[low] : NULL;
}

struct resolved_decl {
	const char *name;
	const char *linkage_name;
	const char *filename;
	unsigned int line;
};

static void resolve_die(const struct dwarf_decl_parse *parse,
			const struct dwarf_decl_die *die,
			struct resolved_decl *resolved, unsigned int depth)
{
	const struct dwarf_decl_die *reference;
	const struct dwarf_decl_cu *cu;

	if (!die || depth == 32)
		return;
	cu = &parse->cus[die->cu];
	if (!resolved->name && die->name)
		resolved->name = die->name;
	if (!resolved->linkage_name && die->linkage_name)
		resolved->linkage_name = die->linkage_name;
	if (!resolved->filename && die->have_file)
		resolved->filename = find_file(cu, die->file);
	if (!resolved->line && die->have_line)
		resolved->line = die->line;
	if (die->have_abstract_origin) {
		reference = find_die(parse, die->abstract_origin);
		resolve_die(parse, reference, resolved, depth + 1);
	}
	if (die->have_specification) {
		reference = find_die(parse, die->specification);
		resolve_die(parse, reference, resolved, depth + 1);
	}
}

static void clear_parse(struct dwarf_decl_parse *parse)
{
	size_t i, j;

	for (i = 0; i < parse->nr_cus; i++) {
		free(parse->cus[i].name);
		free(parse->cus[i].comp_dir);
		for (j = 0; j < parse->cus[i].nr_files; j++)
			free(parse->cus[i].files[j].name);
		free(parse->cus[i].files);
	}
	for (i = 0; i < parse->nr_dies; i++) {
		free(parse->dies[i].name);
		free(parse->dies[i].linkage_name);
	}
	free(parse->cus);
	free(parse->dies);
}

void dwarf_declarations_destroy(struct dwarf_declarations *decls)
{
	size_t i;

	for (i = 0; i < decls->count; i++) {
		free(decls->entries[i].name);
		free(decls->entries[i].filename);
	}
	free(decls->entries);
	memset(decls, 0, sizeof(*decls));
}

bool dwarf_declarations_parse(FILE *fp, struct dwarf_declarations *decls)
{
	struct dwarf_decl_parse parse = { 0 };
	struct dwarf_decl_cu *cu = NULL;
	struct dwarf_decl_die *die = NULL;
	bool cu_root = false;
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	size_t i;

	memset(decls, 0, sizeof(*decls));
	while ((length = getline(&line, &capacity, fp)) >= 0) {
		uint64_t value;
		const char *end;
		char *text;

		(void)length;
		if (!strncmp(line, "COMPILE_UNIT<header overall offset", 34)) {
			struct dwarf_decl_cu *new_cus = realloc(parse.cus,
				(parse.nr_cus + 1) * sizeof(*parse.cus));

			if (!new_cus)
				goto fail;
			parse.cus = new_cus;
			cu = &parse.cus[parse.nr_cus++];
			memset(cu, 0, sizeof(*cu));
			die = NULL;
			cu_root = false;
			continue;
		}
		if (strstr(line, "DW_TAG_")) {
			die = NULL;
			cu_root = cu && strstr(line, "DW_TAG_compile_unit");
			if (!cu || !strstr(line, "DW_TAG_subprogram")
			    || !parse_hex_after(line, "GOFF=0x", &value, NULL))
				continue;
			{
				struct dwarf_decl_die *new_dies = realloc(parse.dies,
					(parse.nr_dies + 1) * sizeof(*parse.dies));

				if (!new_dies)
					goto fail;
				parse.dies = new_dies;
				die = &parse.dies[parse.nr_dies++];
				memset(die, 0, sizeof(*die));
				die->offset = value;
				die->cu = parse.nr_cus - 1;
			}
			continue;
		}
		if (!cu)
			continue;
		if (cu_root && (text = copy_value(line, "DW_AT_name"))) {
			free(cu->name);
			cu->name = text;
			continue;
		}
		if (cu_root && (text = copy_value(line, "DW_AT_comp_dir"))) {
			free(cu->comp_dir);
			cu->comp_dir = text;
			continue;
		}
		if (parse_attribute_hex(line, "DW_AT_decl_file", &value, &end)
		    && value <= UINT_MAX) {
			while (isspace((unsigned char)*end))
				end++;
			if (*end && !remember_file(cu, value, end))
				goto fail;
			if (die) {
				die->file = value;
				die->have_file = true;
			}
			continue;
		}
		if (!die)
			continue;
		if ((text = copy_value(line, "DW_AT_linkage_name"))
		    || (text = copy_value(line, "DW_AT_MIPS_linkage_name"))) {
			free(die->linkage_name);
			die->linkage_name = text;
		} else if ((text = copy_value(line, "DW_AT_name"))) {
			free(die->name);
			die->name = text;
		} else if (parse_attribute_hex(line, "DW_AT_decl_line", &value,
					       NULL)
			   && value <= UINT_MAX) {
			die->line = value;
			die->have_line = true;
		} else if (parse_attribute_hex(line, "DW_AT_low_pc", &value,
					       NULL)) {
			die->address = value;
			die->have_address = true;
		} else if (strstr(line, "DW_AT_abstract_origin")) {
			/* The -G dwarfdump output supplies the global reference. */
			if (parse_hex_after(line, "GOFF=0x", &value, NULL)) {
				die->abstract_origin = value;
				die->have_abstract_origin = true;
			}
		} else if (strstr(line, "DW_AT_specification")) {
			if (parse_hex_after(line, "GOFF=0x", &value, NULL)) {
				die->specification = value;
				die->have_specification = true;
			}
		}
	}
	free(line);
	line = NULL;
	if (!complete_cu_files(&parse))
		goto fail_no_line;
	qsort(parse.dies, parse.nr_dies, sizeof(*parse.dies), die_compare);
	for (i = 1; i < parse.nr_dies; i++)
		if (parse.dies[i - 1].offset >= parse.dies[i].offset)
			goto fail_no_line;
	for (i = 0; i < parse.nr_dies; i++) {
		const struct dwarf_decl_die *candidate = &parse.dies[i];
		struct resolved_decl resolved = { 0 };
		struct dwarf_decl *entry;
		struct dwarf_decl *new_entries;

		if (!candidate->have_address)
			continue;
		resolve_die(&parse, candidate, &resolved, 0);
		if ((!resolved.name && !resolved.linkage_name)
		    || !resolved.filename || !resolved.line)
			continue;
		new_entries = realloc(decls->entries,
			(decls->count + 1) * sizeof(*decls->entries));
		if (!new_entries)
			goto fail_no_line;
		decls->entries = new_entries;
		entry = &decls->entries[decls->count++];
		entry->address = candidate->address;
		entry->name = strdup(resolved.linkage_name
			? resolved.linkage_name : resolved.name);
		entry->filename = strdup(resolved.filename);
		entry->line = resolved.line;
		if (!entry->name || !entry->filename)
			goto fail_no_line;
	}
	clear_parse(&parse);
	return true;

fail:
	free(line);
fail_no_line:
	clear_parse(&parse);
	dwarf_declarations_destroy(decls);
	return false;
}
