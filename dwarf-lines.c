#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dwarf-lines.h"

static bool token_equal(const char *start, const char *end,
			const char *token)
{
	size_t len = end - start;

	return strlen(token) == len && !memcmp(start, token, len);
}

static bool find_flag(const char *start, const char *end, const char *flag)
{
	while (start < end) {
		const char *token_end;

		while (start < end && isspace((unsigned char)*start))
			start++;
		token_end = start;
		while (token_end < end && !isspace((unsigned char)*token_end))
			token_end++;
		if (token_equal(start, token_end, flag))
			return true;
		start = token_end;
	}
	return false;
}

static unsigned int find_discriminator(const char *start, const char *end)
{
	while (start < end) {
		char *value_end;
		unsigned long value;

		while (start < end && isspace((unsigned char)*start))
			start++;
		if (end - start >= 3 && !memcmp(start, "DI=", 3)) {
			errno = 0;
			value = strtoul(start + 3, &value_end, 0);
			if (!errno && value_end > start + 3 && value <= UINT32_MAX)
				return value;
		}
		while (start < end && !isspace((unsigned char)*start))
			start++;
	}
	return 0;
}

static char *parse_filename(const char *uri)
{
	const char *end;
	const char *start;
	size_t len;
	char *filename;

	start = strchr(uri, '"');
	if (!start)
		return NULL;
	start++;
	end = strchr(start, '"');
	if (!end)
		return NULL;

	len = end - start;
	filename = malloc(len + 1);
	if (!filename)
		return NULL;
	memcpy(filename, start, len);
	filename[len] = '\0';
	return filename;
}

bool dwarf_line_parse(const char *text, struct dwarf_line_row *row)
{
	const char *flags_end;
	const char *flags;
	const char *uri;
	const char *s;
	char *end;
	unsigned long line;

	memset(row, 0, sizeof(*row));
	if (strncmp(text, "0x", 2))
		return false;

	errno = 0;
	row->address = strtoull(text, &end, 16);
	if (errno || end == text)
		return false;
	s = end;
	while (isspace((unsigned char)*s))
		s++;
	if (*s++ != '[')
		return false;
	while (isspace((unsigned char)*s))
		s++;

	errno = 0;
	line = strtoul(s, &end, 10);
	if (errno || end == s || line == 0 || line > UINT32_MAX)
		return false;
	row->line = line;

	s = strchr(end, ']');
	if (!s)
		return false;
	flags = s + 1;
	uri = strstr(flags, "uri:");
	flags_end = uri ? uri : flags + strlen(flags);
	row->is_stmt = find_flag(flags, flags_end, "NS");
	row->end_sequence = find_flag(flags, flags_end, "ET");
	row->discriminator = find_discriminator(flags, flags_end);
	if (uri) {
		row->filename = parse_filename(uri);
		if (!row->filename)
			return false;
	}
	return true;
}

void dwarf_line_row_clear(struct dwarf_line_row *row)
{
	free(row->filename);
	row->filename = NULL;
}
