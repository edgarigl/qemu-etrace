#include <fcntl.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "run.h"

static void test_path_lookup(void)
{
	GError *error = NULL;
	char *old_path = g_strdup(g_getenv("PATH"));
	char *tmpdir = g_dir_make_tmp("qemu-etrace-run-XXXXXX", &error);
	char *tool;
	char *argv[] = { "qemu-etrace-path-tool", NULL };
	int nullfd;
	int stdio[3];
	int status;
	pid_t pid;

	g_assert_no_error(error);
	g_assert_nonnull(tmpdir);
	tool = g_build_filename(tmpdir, argv[0], NULL);
	g_assert_cmpint(symlink("/bin/true", tool), ==, 0);
	g_assert_true(g_setenv("PATH", tmpdir, TRUE));

	nullfd = open("/dev/null", O_RDWR);
	g_assert_cmpint(nullfd, >=, 0);
	stdio[0] = nullfd;
	stdio[1] = nullfd;
	stdio[2] = nullfd;
	pid = run(argv[0], argv, stdio);
	g_assert_cmpint(pid, >, 0);
	g_assert_cmpint(waitpid(pid, &status, 0), ==, pid);
	g_assert_true(WIFEXITED(status));
	g_assert_cmpint(WEXITSTATUS(status), ==, 0);

	close(nullfd);
	if (old_path) {
		g_assert_true(g_setenv("PATH", old_path, TRUE));
	} else {
		g_unsetenv("PATH");
	}
	g_assert_cmpint(unlink(tool), ==, 0);
	g_assert_cmpint(rmdir(tmpdir), ==, 0);
	g_free(tool);
	g_free(tmpdir);
	g_free(old_path);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/run/path-lookup", test_path_lookup);

	return g_test_run();
}
