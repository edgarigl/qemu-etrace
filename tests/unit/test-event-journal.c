#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#include "event-journal.h"

static struct event_journal *make_journal(FILE **fp, uint64_t limit,
					 uint64_t decoded_limit,
					 const void *data, size_t len)
{
	struct event_journal *j;

	*fp = tmpfile();
	g_assert_nonnull(*fp);
	j = event_journal_new(*fp, limit, decoded_limit);
	g_assert_true(event_journal_append(j, data, len));
	return j;
}

static void check_read(struct event_journal *j, const uint8_t *data, size_t len)
{
	uint8_t buffer[4093];
	size_t offset = 0;
	ssize_t got;

	g_assert_true(event_journal_rewind(j));
	while ((got = event_journal_read(j, buffer, sizeof(buffer))) > 0) {
		g_assert_cmpuint(offset + got, <=, len);
		g_assert_cmpmem(buffer, got, data + offset, got);
		offset += got;
	}
	g_assert_cmpint(got, ==, 0);
	g_assert_cmpuint(offset, ==, len);
	g_assert_null(event_journal_error(j));
}

static void test_roundtrip(void)
{
	size_t size = EVENT_JOURNAL_FRAME_SIZE * 3 + 17;
	uint8_t *data = g_malloc(size);
	GRand *random = g_rand_new_with_seed(123);
	struct event_journal_stats stats;
	struct event_journal *j;
	FILE *fp = tmpfile();
	char *digest;
	size_t i;

	g_assert_nonnull(fp);
	for (i = 0; i < size; i++)
		data[i] = g_rand_int(random);
	j = event_journal_new(fp, 2 * size, size);
	for (i = 0; i < size; i += 257)
		g_assert_true(event_journal_append(j, data + i, MIN(257, size - i)));
	g_assert_true(event_journal_finish(j));
	event_journal_get_stats(j, &stats);
	g_assert_cmpuint(stats.logical_bytes, ==, size);
	g_assert_cmpuint(stats.frames, ==, 4);
	g_assert_cmpuint(stats.stored_bytes, ==, (uint64_t)ftello(fp));
	g_assert_cmpuint(stats.buffered_logical_bytes, ==, 0);
	g_assert_cmpuint(stats.reserved_bytes, ==, 0);
	digest = g_compute_checksum_for_data(G_CHECKSUM_SHA256, data, size);
	g_assert_cmpstr(event_journal_digest(j), ==, digest);
	check_read(j, data, size);
	check_read(j, data, size);
	event_journal_free(j);
	fclose(fp);
	g_free(digest);
	g_rand_free(random);
	g_free(data);
}

static void test_limits(void)
{
	size_t size = EVENT_JOURNAL_FRAME_SIZE * 3;
	uint8_t *data = g_malloc0(size);
	struct event_journal_stats stats;
	struct event_journal *j;
	FILE *fp;
	uint64_t exact;

	j = make_journal(&fp, UINT64_MAX, size, data, size);
	g_assert_true(event_journal_finish(j));
	event_journal_get_stats(j, &stats);
	exact = stats.stored_bytes;
	g_assert_cmpuint(exact, <, size / 10);
	event_journal_free(j);
	fclose(fp);

	j = make_journal(&fp, exact, size, data, size);
	check_read(j, data, size);
	event_journal_get_stats(j, &stats);
	g_assert_cmpuint(stats.stored_bytes, ==, exact);
	event_journal_free(j);
	fclose(fp);

	fp = tmpfile();
	j = event_journal_new(fp, exact - 1, size);
	g_assert_false(event_journal_append(j, data, size)
		       && event_journal_finish(j));
	g_assert_cmpstr(event_journal_error(j), ==, "event spool limit exceeded");
	event_journal_get_stats(j, &stats);
	g_assert_cmpuint(stats.stored_bytes, <=, exact - 1);
	g_assert_false(event_journal_rewind(j));
	event_journal_free(j);
	fclose(fp);

	fp = tmpfile();
	j = event_journal_new(fp, exact, size - 1);
	g_assert_false(event_journal_append(j, data, size));
	g_assert_cmpstr(event_journal_error(j), ==,
			"event spool decoded limit exceeded");
	g_assert_cmpint(ftello(fp), ==, 0);
	event_journal_free(j);
	fclose(fp);
	g_free(data);
}

static void test_empty(void)
{
	FILE *fp;
	struct event_journal *j = make_journal(&fp, 80, 0, "", 0);

	check_read(j, (const uint8_t *)"", 0);
	event_journal_free(j);
	fclose(fp);
}

static bool read_all(struct event_journal *j)
{
	uint8_t buffer[1024];
	ssize_t got;

	if (!event_journal_rewind(j))
		return false;
	do {
		got = event_journal_read(j, buffer, sizeof(buffer));
	} while (got > 0);
	return got == 0;
}

static void test_damage(void)
{
	uint8_t data[1024] = { 1, 2, 3 };
	struct event_journal_stats stats;
	struct event_journal *j;
	FILE *fp;
	size_t size, offset;

	j = make_journal(&fp, UINT64_MAX, sizeof(data), data, sizeof(data));
	g_assert_true(event_journal_finish(j));
	event_journal_get_stats(j, &stats);
	size = stats.stored_bytes;
	event_journal_free(j);
	fclose(fp);

	for (offset = 0; offset < size; offset++) {
		int value;

		j = make_journal(&fp, size, sizeof(data), data, sizeof(data));
		g_assert_true(event_journal_finish(j));
		g_assert_cmpint(ftruncate(fileno(fp), offset), ==, 0);
		g_assert_false(read_all(j));
		g_assert_nonnull(event_journal_error(j));
		event_journal_free(j);
		fclose(fp);

		j = make_journal(&fp, size, sizeof(data), data, sizeof(data));
		g_assert_true(event_journal_finish(j));
		g_assert_cmpint(fseeko(fp, offset, SEEK_SET), ==, 0);
		value = fgetc(fp);
		g_assert_cmpint(value, !=, EOF);
		g_assert_cmpint(fseeko(fp, offset, SEEK_SET), ==, 0);
		g_assert_cmpint(fputc(value ^ 0x80, fp), !=, EOF);
		g_assert_cmpint(fflush(fp), ==, 0);
		g_assert_false(read_all(j));
		g_assert_nonnull(event_journal_error(j));
		event_journal_free(j);
		fclose(fp);
	}
}

static void test_frame_order(void)
{
	size_t size = EVENT_JOURNAL_FRAME_SIZE * 2;
	uint8_t *data = g_malloc(size);
	uint8_t *disk;
	struct event_journal_stats stats;
	struct event_journal *j;
	FILE *fp;
	uint32_t encoded_size;
	size_t frame_size, second_size;

	memset(data, 1, size / 2);
	memset(data + size / 2, 2, size / 2);
	j = make_journal(&fp, size, size, data, size);
	g_assert_true(event_journal_finish(j));
	event_journal_get_stats(j, &stats);
	disk = g_malloc(stats.stored_bytes);
	rewind(fp);
	g_assert_cmpuint(fread(disk, 1, stats.stored_bytes, fp), ==,
			 stats.stored_bytes);
	memcpy(&encoded_size, disk + 16, sizeof(encoded_size));
	frame_size = 16 + GUINT32_FROM_LE(encoded_size);
	memcpy(&encoded_size, disk + 16 + frame_size, sizeof(encoded_size));
	second_size = 16 + GUINT32_FROM_LE(encoded_size);
	/* Swap intact frames: their CRCs still pass, the stream digest must fail. */
	g_assert_cmpuint(stats.stored_bytes, ==, 16 + frame_size + second_size + 64);
	g_assert_cmpint(fseeko(fp, 16, SEEK_SET), ==, 0);
	g_assert_cmpuint(fwrite(disk + 16 + frame_size, 1, second_size, fp), ==,
			 second_size);
	g_assert_cmpuint(fwrite(disk + 16, 1, frame_size, fp), ==, frame_size);
	g_assert_cmpint(fflush(fp), ==, 0);
	g_assert_false(read_all(j));
	g_assert_cmpstr(event_journal_error(j), ==,
			"ordered event spool digest or count mismatch");
	event_journal_free(j);
	fclose(fp);
	g_free(disk);
	g_free(data);
}

static ssize_t fail_write(void *cookie, const char *data, size_t len)
{
	size_t *allowance = cookie;

	(void)data;
	if (len > *allowance) {
		errno = ENOSPC;
		return -1;
	}
	*allowance -= len;
	return len;
}

static void test_io_failure(void)
{
	size_t allowances[] = { 0, 16, 32 };
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(allowances); i++) {
		FILE *fp = fopencookie(&allowances[i], "w",
			(cookie_io_functions_t) { .write = fail_write });
		struct event_journal *j;
		uint8_t data[EVENT_JOURNAL_FRAME_SIZE] = { 0 };

		g_assert_nonnull(fp);
		setvbuf(fp, NULL, _IONBF, 0);
		j = event_journal_new(fp, UINT64_MAX, UINT64_MAX);
		g_assert_false(event_journal_append(j, data, sizeof(data))
			       && event_journal_finish(j));
		g_assert_nonnull(event_journal_error(j));
		g_assert_false(event_journal_rewind(j));
		event_journal_free(j);
		fclose(fp);
	}
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/event-journal/roundtrip", test_roundtrip);
	g_test_add_func("/event-journal/limits", test_limits);
	g_test_add_func("/event-journal/empty", test_empty);
	g_test_add_func("/event-journal/damage", test_damage);
	g_test_add_func("/event-journal/frame-order", test_frame_order);
	g_test_add_func("/event-journal/io-failure", test_io_failure);
	return g_test_run();
}
