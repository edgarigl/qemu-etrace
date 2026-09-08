/* Bounded, lossless internal event storage. SPDX-License-Identifier: GPL-2.0-only */
#include <string.h>
#include <glib.h>
#include <zlib.h>

#include "event-journal.h"

/* All integers in the container are little endian. Payloads are opaque. */
static const uint8_t magic[8] = { 'E', 'T', 'J', 'R', 'N', 'L', '0', '1' };

enum {
	FRAME_RAW = 0,
	FRAME_ZLIB = 1,
	FRAME_END = 2,
	HEADER_SIZE = 16,
	FRAME_HEADER_SIZE = 16,
	FOOTER_SIZE = 48,
	END_SIZE = FRAME_HEADER_SIZE + FOOTER_SIZE,
};

struct event_journal {
	FILE *fp;
	uint64_t stored_limit;
	uint64_t decoded_limit;
	uint64_t logical_bytes;
	uint64_t stored_bytes;
	uint64_t frames;
	uint64_t read_bytes;
	uint64_t read_frames;
	size_t used;
	size_t cursor;
	uint8_t raw[EVENT_JOURNAL_FRAME_SIZE];
	uint8_t *encoded;
	uLong encoded_capacity;
	GChecksum *write_hash;
	GChecksum *read_hash;
	uint8_t digest[32];
	const char *error;
	bool started;
	bool finished;
	bool reading;
	bool eof;
};

static bool fail(struct event_journal *j, const char *error)
{
	if (!j->error)
		j->error = error;
	return false;
}

static void put32(uint8_t *p, uint32_t value)
{
	value = GUINT32_TO_LE(value);
	memcpy(p, &value, sizeof(value));
}

static uint32_t get32(const uint8_t *p)
{
	uint32_t value;

	memcpy(&value, p, sizeof(value));
	return GUINT32_FROM_LE(value);
}

static void put64(uint8_t *p, uint64_t value)
{
	value = GUINT64_TO_LE(value);
	memcpy(p, &value, sizeof(value));
}

static uint64_t get64(const uint8_t *p)
{
	uint64_t value;

	memcpy(&value, p, sizeof(value));
	return GUINT64_FROM_LE(value);
}

static bool capacity(struct event_journal *j, uint64_t len, uint64_t reserved)
{
	if (j->stored_bytes > j->stored_limit
	    || reserved > j->stored_limit - j->stored_bytes
	    || len > j->stored_limit - j->stored_bytes - reserved)
		return fail(j, "event spool limit exceeded");
	return true;
}

static bool write_bytes(struct event_journal *j, const void *data, size_t len)
{
	if (fwrite(data, 1, len, j->fp) != len || ferror(j->fp))
		return fail(j, "unable to write ordered event spool");
	j->stored_bytes += len;
	return true;
}

static bool read_bytes(struct event_journal *j, void *data, size_t len)
{
	if (fread(data, 1, len, j->fp) != len)
		return fail(j, ferror(j->fp) ? "unable to read ordered event spool"
			    : "truncated ordered event spool");
	return true;
}

static bool start(struct event_journal *j)
{
	uint8_t header[HEADER_SIZE] = { 0 };

	if (j->started)
		return true;
	memcpy(header, magic, sizeof(magic));
	put32(header + 8, EVENT_JOURNAL_FRAME_SIZE);
	if (!capacity(j, sizeof(header), END_SIZE)
	    || !write_bytes(j, header, sizeof(header)))
		return false;
	j->started = true;
	return true;
}

static bool flush_frame(struct event_journal *j)
{
	uint8_t header[FRAME_HEADER_SIZE];
	uLongf encoded_len = j->encoded_capacity;
	const uint8_t *payload = j->encoded;
	uint32_t flags = FRAME_ZLIB;

	if (!j->used)
		return true;
	if (compress2(j->encoded, &encoded_len, j->raw, j->used,
		      Z_BEST_SPEED) != Z_OK)
		return fail(j, "unable to compress ordered event spool");
	if (encoded_len >= j->used) {
		payload = j->raw;
		encoded_len = j->used;
		flags = FRAME_RAW;
	}
	put32(header, encoded_len);
	put32(header + 4, j->used);
	put32(header + 8, crc32(0, payload, encoded_len));
	put32(header + 12, flags);
	/* Include the entire encoded frame and terminal record before writing. */
	if (!capacity(j, sizeof(header) + encoded_len, END_SIZE)
	    || !write_bytes(j, header, sizeof(header))
	    || !write_bytes(j, payload, encoded_len))
		return false;
	j->frames++;
	j->used = 0;
	return true;
}

struct event_journal *event_journal_new(FILE *fp, uint64_t stored_limit,
				       uint64_t decoded_limit)
{
	struct event_journal *j = g_new0(struct event_journal, 1);

	j->fp = fp;
	j->stored_limit = stored_limit;
	j->decoded_limit = decoded_limit;
	j->encoded_capacity = compressBound(EVENT_JOURNAL_FRAME_SIZE);
	j->encoded = g_malloc(j->encoded_capacity);
	j->write_hash = g_checksum_new(G_CHECKSUM_SHA256);
	j->read_hash = g_checksum_new(G_CHECKSUM_SHA256);
	return j;
}

bool event_journal_append(struct event_journal *j, const void *data, size_t len)
{
	const uint8_t *p = data;

	if (j->error)
		return false;
	if (j->finished)
		return fail(j, "append to finished ordered event spool");
	if (j->logical_bytes > j->decoded_limit
	    || len > j->decoded_limit - j->logical_bytes)
		return fail(j, "event spool decoded limit exceeded");
	if (!start(j))
		return false;
	j->logical_bytes += len;
	g_checksum_update(j->write_hash, p, len);
	while (len) {
		size_t chunk = MIN(len, sizeof(j->raw) - j->used);

		memcpy(j->raw + j->used, p, chunk);
		j->used += chunk;
		p += chunk;
		len -= chunk;
		if (j->used == sizeof(j->raw) && !flush_frame(j))
			return false;
	}
	return true;
}

bool event_journal_finish(struct event_journal *j)
{
	uint8_t end[END_SIZE] = { 0 };
	gsize digest_len = sizeof(j->digest);

	if (j->error)
		return false;
	if (j->finished)
		return true;
	if (!start(j) || !flush_frame(j))
		return false;
	g_checksum_get_digest(j->write_hash, j->digest, &digest_len);
	put32(end + 12, FRAME_END);
	put64(end + FRAME_HEADER_SIZE, j->logical_bytes);
	put64(end + FRAME_HEADER_SIZE + 8, j->frames);
	memcpy(end + FRAME_HEADER_SIZE + 16, j->digest, sizeof(j->digest));
	if (!capacity(j, sizeof(end), 0) || !write_bytes(j, end, sizeof(end)))
		return false;
	if (fflush(j->fp) != 0)
		return fail(j, "unable to flush ordered event spool");
	j->finished = true;
	return true;
}

bool event_journal_rewind(struct event_journal *j)
{
	uint8_t header[HEADER_SIZE];

	if (!event_journal_finish(j))
		return false;
	if (fseeko(j->fp, 0, SEEK_SET) != 0)
		return fail(j, "unable to rewind ordered event spool");
	if (!read_bytes(j, header, sizeof(header)))
		return false;
	if (memcmp(header, magic, sizeof(magic))
	    || get32(header + 8) != EVENT_JOURNAL_FRAME_SIZE
	    || get32(header + 12))
		return fail(j, "invalid ordered event spool header");
	j->used = j->cursor = 0;
	j->read_bytes = j->read_frames = 0;
	j->reading = true;
	j->eof = false;
	g_checksum_reset(j->read_hash);
	return true;
}

static bool read_frame(struct event_journal *j)
{
	uint8_t header[FRAME_HEADER_SIZE];
	uint32_t stored, decoded, checksum, flags;

	if (!read_bytes(j, header, sizeof(header)))
		return false;
	stored = get32(header);
	decoded = get32(header + 4);
	checksum = get32(header + 8);
	flags = get32(header + 12);
	if (flags == FRAME_END) {
		uint8_t footer[FOOTER_SIZE];
		uint8_t digest[32];
		gsize digest_len = sizeof(digest);

		if (stored || decoded || checksum)
			return fail(j, "invalid ordered event spool terminator");
		if (!read_bytes(j, footer, sizeof(footer)))
			return false;
		g_checksum_get_digest(j->read_hash, digest, &digest_len);
		if (get64(footer) != j->read_bytes
		    || get64(footer + 8) != j->read_frames
		    || j->read_bytes != j->logical_bytes
		    || j->read_frames != j->frames
		    || memcmp(footer + 16, digest, sizeof(digest))
		    || memcmp(j->digest, digest, sizeof(digest)))
			return fail(j, "ordered event spool digest or count mismatch");
		if (fgetc(j->fp) != EOF)
			return fail(j, "trailing data in ordered event spool");
		if (ferror(j->fp))
			return fail(j, "unable to read ordered event spool");
		j->eof = true;
		return true;
	}
	if ((flags != FRAME_RAW && flags != FRAME_ZLIB)
	    || !stored || !decoded || stored > EVENT_JOURNAL_FRAME_SIZE
	    || decoded > EVENT_JOURNAL_FRAME_SIZE
	    || j->read_bytes > j->logical_bytes
	    || decoded > j->logical_bytes - j->read_bytes
	    || j->read_frames >= j->frames)
		return fail(j, "invalid ordered event spool frame");
	if (!read_bytes(j, j->encoded, stored))
		return false;
	if (crc32(0, j->encoded, stored) != checksum)
		return fail(j, "ordered event spool frame checksum mismatch");
	if (flags == FRAME_RAW) {
		if (stored != decoded)
			return fail(j, "invalid raw ordered event spool frame");
		memcpy(j->raw, j->encoded, decoded);
	} else {
		uLongf size = sizeof(j->raw);
		uLong consumed = stored;

		if (uncompress2(j->raw, &size, j->encoded, &consumed) != Z_OK
		    || size != decoded || consumed != stored)
			return fail(j, "corrupt compressed ordered event spool frame");
	}
	g_checksum_update(j->read_hash, j->raw, decoded);
	j->read_bytes += decoded;
	j->read_frames++;
	j->used = decoded;
	j->cursor = 0;
	return true;
}

ssize_t event_journal_read(struct event_journal *j, void *data, size_t len)
{
	uint8_t *p = data;
	size_t total = 0;

	if (j->error)
		return -1;
	if (!j->reading) {
		fail(j, "read before rewinding ordered event spool");
		return -1;
	}
	while (total < len && !j->eof) {
		size_t chunk;

		if (j->cursor == j->used) {
			if (!read_frame(j))
				return -1;
			if (j->eof)
				break;
		}
		chunk = MIN(len - total, j->used - j->cursor);
		memcpy(p + total, j->raw + j->cursor, chunk);
		j->cursor += chunk;
		total += chunk;
	}
	return total;
}

const char *event_journal_error(const struct event_journal *j)
{
	return j->error;
}

const char *event_journal_digest(struct event_journal *j)
{
	return j->finished ? g_checksum_get_string(j->write_hash) : NULL;
}

void event_journal_get_stats(const struct event_journal *j,
			     struct event_journal_stats *stats)
{
	*stats = (struct event_journal_stats) {
		.logical_bytes = j->logical_bytes,
		.stored_bytes = j->stored_bytes,
		.frames = j->frames,
		.buffered_logical_bytes = j->finished ? 0 : j->used,
		.reserved_bytes = j->finished ? 0 : END_SIZE,
	};
}

void event_journal_free(struct event_journal *j)
{
	if (!j)
		return;
	g_checksum_free(j->read_hash);
	g_checksum_free(j->write_hash);
	g_free(j->encoded);
	g_free(j);
}
