#include <fcntl.h>
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "etrace-format.h"
#include "qemu-plugin.h"

struct qemu_plugin_insn {
	uint64_t vaddr;
	size_t size;
};

struct qemu_plugin_tb {
	uint64_t vaddr;
	struct qemu_plugin_insn *insns;
	size_t n_insns;
};

static qemu_plugin_vcpu_tb_trans_cb_t trans_cb;
static qemu_plugin_vcpu_udata_cb_t exec_cb;
static qemu_plugin_udata_cb_t exit_cb;
#if QEMU_PLUGIN_VERSION >= 7
static void *trans_data;
#endif
static void *exec_data;
static void *exit_data;

extern int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
			       int argc, char **argv);

#if QEMU_PLUGIN_VERSION >= 7
void qemu_plugin_register_vcpu_tb_trans_cb(
	qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb, void *userdata)
{
	trans_cb = cb;
	trans_data = userdata;
}
#else
void qemu_plugin_register_vcpu_tb_trans_cb(
	qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb)
{
	trans_cb = cb;
}
#endif

void qemu_plugin_register_vcpu_tb_exec_cb(
	struct qemu_plugin_tb *tb, qemu_plugin_vcpu_udata_cb_t cb,
	enum qemu_plugin_cb_flags flags, void *userdata)
{
	exec_cb = cb;
	exec_data = userdata;
}

void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id,
				     qemu_plugin_udata_cb_t cb,
				     void *userdata)
{
	exit_cb = cb;
	exit_data = userdata;
}

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
	return tb->n_insns;
}

uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb)
{
	return tb->vaddr;
}

struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t index)
{
	return &tb->insns[index];
}

uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn)
{
	return insn->vaddr;
}

size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn)
{
	return insn->size;
}

static void read_data(const uint8_t **cursor, void *value, size_t size)
{
	memcpy(value, *cursor, size);
	*cursor += size;
}

static void test_execution_trace(void)
{
	struct qemu_plugin_insn insns[] = {
		{ .vaddr = 0x1000, .size = 4 },
		{ .vaddr = 0x1004, .size = 4 },
	};
	struct qemu_plugin_tb tb = {
		.vaddr = 0x1000,
		.insns = insns,
		.n_insns = G_N_ELEMENTS(insns),
	};
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	struct etrace_info_data info_data;
	struct etrace_entry64 entry;
	struct etrace_arch arch;
	struct etrace_hdr hdr;
	char *arg;
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	uint64_t start_time;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	arg = g_strdup_printf("out=%s", path);

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, 0);
	g_assert_nonnull(trans_cb);
	g_assert_nonnull(exit_cb);
#if QEMU_PLUGIN_VERSION >= 7
	trans_cb(&tb, trans_data);
#else
	trans_cb(1, &tb);
#endif
	g_assert_nonnull(exec_cb);
	exec_cb(3, exec_data);
#if QEMU_PLUGIN_VERSION >= 7
	exit_cb(exit_data);
#else
	exit_cb(1, exit_data);
#endif

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;

	read_data(&cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_INFO);
	g_assert_cmpuint(hdr.len, ==, sizeof(info_data));
	read_data(&cursor, &info_data, sizeof(info_data));
	g_assert_cmpuint(info_data.version.major, ==, 0);

	read_data(&cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_ARCH);
	g_assert_cmpuint(hdr.len, ==, sizeof(arch));
	read_data(&cursor, &arch, sizeof(arch));
	g_assert_cmpuint(arch.guest.arch_bits, ==, 64);

	read_data(&cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_EXEC);
	g_assert_cmpuint(hdr.unit_id, ==, 3);
	read_data(&cursor, &start_time, sizeof(start_time));
	read_data(&cursor, &entry, sizeof(entry));
	g_assert_cmpuint(start_time, ==, 0);
	g_assert_cmpuint(entry.duration, ==, 0);
	g_assert_cmpuint(entry.start, ==, 0x1000);
	g_assert_cmpuint(entry.end, ==, 0x1008);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}

static void test_32bit_execution_trace(void)
{
	struct qemu_plugin_insn insn = { .vaddr = 0x2000, .size = 2 };
	struct qemu_plugin_tb tb = {
		.vaddr = 0x2000,
		.insns = &insn,
		.n_insns = 1,
	};
	qemu_info_t info = {
		.target_name = "arm",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	struct etrace_info_data info_data;
	struct etrace_entry32 entry;
	struct etrace_arch arch;
	struct etrace_hdr hdr;
	char *arg;
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	uint64_t start_time;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	arg = g_strdup_printf("out=%s", path);

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, 0);
#if QEMU_PLUGIN_VERSION >= 7
	trans_cb(&tb, trans_data);
#else
	trans_cb(1, &tb);
#endif
	exec_cb(2, exec_data);
#if QEMU_PLUGIN_VERSION >= 7
	exit_cb(exit_data);
#else
	exit_cb(1, exit_data);
#endif

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	read_data(&cursor, &hdr, sizeof(hdr));
	read_data(&cursor, &info_data, sizeof(info_data));
	read_data(&cursor, &hdr, sizeof(hdr));
	read_data(&cursor, &arch, sizeof(arch));
	g_assert_cmpuint(arch.guest.arch_bits, ==, 32);
	read_data(&cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_EXEC);
	read_data(&cursor, &start_time, sizeof(start_time));
	read_data(&cursor, &entry, sizeof(entry));
	g_assert_cmpuint(entry.start, ==, 0x2000);
	g_assert_cmpuint(entry.end, ==, 0x2002);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/plugin/execution-trace", test_execution_trace);
	g_test_add_func("/plugin/32bit-execution-trace",
			test_32bit_execution_trace);

	return g_test_run();
}
