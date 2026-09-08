#ifndef EVENT_JOURNAL_H
#define EVENT_JOURNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define EVENT_JOURNAL_FRAME_SIZE (64 * 1024)

struct event_journal;

struct event_journal_stats {
	uint64_t logical_bytes;
	uint64_t stored_bytes;
	uint64_t frames;
	size_t buffered_logical_bytes;
	size_t reserved_bytes;
};

/* The caller owns fp. Any error makes subsequent operations fail. */
struct event_journal *event_journal_new(FILE *fp, uint64_t stored_limit,
				       uint64_t decoded_limit);
bool event_journal_append(struct event_journal *j, const void *data, size_t len);
bool event_journal_finish(struct event_journal *j);
bool event_journal_rewind(struct event_journal *j);
ssize_t event_journal_read(struct event_journal *j, void *data, size_t len);
const char *event_journal_error(const struct event_journal *j);
const char *event_journal_digest(struct event_journal *j);
void event_journal_get_stats(const struct event_journal *j,
			     struct event_journal_stats *stats);
void event_journal_free(struct event_journal *j);

#endif
