#include <glib.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include "excludes.h"

static void test_match(void)
{
	char *path = NULL;
	int fd = g_file_open_tmp("qemu-etrace-excludes-XXXXXX", &path, NULL);
	FILE *fp;
	void *excludes;

	g_assert_cmpint(fd, >=, 0);
	fp = fdopen(fd, "w");
	g_assert_nonnull(fp);
	fputs("source.c:12\n", fp);
	fclose(fp);

	excludes = excludes_create(path);
	g_assert_nonnull(excludes);
	g_assert_true(excludes_match(excludes, "source.c", 12));
	g_assert_false(excludes_match(excludes, "source.c", 13));
	excludes_destroy(excludes);

	unlink(path);
	g_free(path);
}

static void test_reject_long_filename(void)
{
	char *path = NULL;
	int fd = g_file_open_tmp("qemu-etrace-excludes-XXXXXX", &path, NULL);
	FILE *fp;
	unsigned int i;
	void *excludes;

	g_assert_cmpint(fd, >=, 0);
	fp = fdopen(fd, "w");
	g_assert_nonnull(fp);
	for (i = 0; i < PATH_MAX; i++)
		fputc('a', fp);
	fputs(":12\n", fp);
	fclose(fp);

	excludes = excludes_create(path);
	g_assert_null(excludes);

	unlink(path);
	g_free(path);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/excludes/match", test_match);
	g_test_add_func("/excludes/reject-long-filename",
			test_reject_long_filename);

	return g_test_run();
}
