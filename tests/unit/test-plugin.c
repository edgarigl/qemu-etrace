#include <fcntl.h>
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "etrace-format.h"
#include "qemu-plugin.h"

struct qemu_plugin_insn {
	uint64_t vaddr;
	size_t size;
	qemu_plugin_vcpu_udata_cb_t exec_cb;
	void *exec_data;
};

struct qemu_plugin_tb {
	uint64_t vaddr;
	struct qemu_plugin_insn *insns;
	size_t n_insns;
	qemu_plugin_vcpu_udata_cb_t exec_cb;
	void *exec_data;
};

static qemu_plugin_vcpu_tb_trans_cb_t trans_cb;
static qemu_plugin_udata_cb_t exit_cb;
#if QEMU_PLUGIN_VERSION >= 7
static void *trans_data;
#endif
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
	tb->exec_cb = cb;
	tb->exec_data = userdata;
}

void qemu_plugin_register_vcpu_insn_exec_cb(
	struct qemu_plugin_insn *insn, qemu_plugin_vcpu_udata_cb_t cb,
	enum qemu_plugin_cb_flags flags, void *userdata)
{
	insn->exec_cb = cb;
	insn->exec_data = userdata;
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

static void translate_tb(struct qemu_plugin_tb *tb)
{
#if QEMU_PLUGIN_VERSION >= 7
	trans_cb(tb, trans_data);
#else
	trans_cb(1, tb);
#endif
}

static void execute_tb_prefix(struct qemu_plugin_tb *tb,
			      unsigned int cpu_index, size_t n_insns)
{
	size_t i;

	g_assert_cmpuint(n_insns, <=, tb->n_insns);
	if (tb->exec_cb)
		tb->exec_cb(cpu_index, tb->exec_data);
	for (i = 0; i < n_insns; i++) {
		struct qemu_plugin_insn *insn = &tb->insns[i];

		if (insn->exec_cb)
			insn->exec_cb(cpu_index, insn->exec_data);
	}
}

static void finish_plugin(void)
{
#if QEMU_PLUGIN_VERSION >= 7
	exit_cb(exit_data);
#else
	exit_cb(1, exit_data);
#endif
}

struct callback_observation {
	unsigned int calls;
	unsigned int cpu_index;
};

static void observe_instruction(unsigned int cpu_index, void *userdata)
{
	struct callback_observation *observation = userdata;

	observation->calls++;
	observation->cpu_index = cpu_index;
}

static void test_instruction_callback_model(void)
{
	struct callback_observation observations[3] = { 0 };
	struct qemu_plugin_insn insns[] = {
		{ .vaddr = 0x1000, .size = 2 },
		{ .vaddr = 0x1002, .size = 4 },
		{ .vaddr = 0x1006, .size = 3 },
	};
	struct qemu_plugin_tb tb = {
		.vaddr = 0x1000,
		.insns = insns,
		.n_insns = G_N_ELEMENTS(insns),
	};
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(insns); i++) {
		qemu_plugin_register_vcpu_insn_exec_cb(
			&insns[i], observe_instruction, QEMU_PLUGIN_CB_NO_REGS,
			&observations[i]);
	}

	execute_tb_prefix(&tb, 7, 2);

	g_assert_cmpuint(observations[0].calls, ==, 1);
	g_assert_cmpuint(observations[0].cpu_index, ==, 7);
	g_assert_cmpuint(observations[1].calls, ==, 1);
	g_assert_cmpuint(observations[1].cpu_index, ==, 7);
	g_assert_cmpuint(observations[2].calls, ==, 0);
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
	translate_tb(&tb);
	g_assert_nonnull(tb.exec_cb);
	execute_tb_prefix(&tb, 3, tb.n_insns);
	finish_plugin();

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
	translate_tb(&tb);
	execute_tb_prefix(&tb, 2, tb.n_insns);
	finish_plugin();

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

static void test_gzip_execution_trace(void)
{
	struct qemu_plugin_insn insn = { .vaddr = 0x3000, .size = 4 };
	struct qemu_plugin_tb tb = {
		.vaddr = 0x3000,
		.insns = &insn,
		.n_insns = 1,
	};
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	struct etrace_entry64 entry;
	struct etrace_hdr hdr;
	const uint8_t *cursor;
	char *args[3];
	char *path = NULL;
	uint8_t contents[256];
	uint64_t start_time;
	gzFile input;
	int fd;
	int length;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX.gz", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "compress=gzip";
	args[2] = "level=1";

	g_assert_cmpint(qemu_plugin_install(1, &info, 3, args), ==, 0);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 4, tb.n_insns);
	finish_plugin();

	input = gzopen(path, "rb");
	g_assert_nonnull(input);
	length = gzread(input, contents, sizeof(contents));
	g_assert_cmpint(length, >, 0);
	g_assert_cmpint(gzclose(input), ==, Z_OK);

	cursor = contents;
	read_data(&cursor, &hdr, sizeof(hdr));
	cursor += hdr.len;
	read_data(&cursor, &hdr, sizeof(hdr));
	cursor += hdr.len;
	read_data(&cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_EXEC);
	g_assert_cmpuint(hdr.unit_id, ==, 4);
	read_data(&cursor, &start_time, sizeof(start_time));
	read_data(&cursor, &entry, sizeof(entry));
	g_assert_cmpuint(entry.start, ==, 0x3000);
	g_assert_cmpuint(entry.end, ==, 0x3004);
	g_assert_cmpuint(cursor - contents, ==, length);

	unlink(path);
	g_free(args[0]);
	g_free(path);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/plugin/instruction-callback-model",
			test_instruction_callback_model);
	g_test_add_func("/plugin/execution-trace", test_execution_trace);
	g_test_add_func("/plugin/32bit-execution-trace",
			test_32bit_execution_trace);
	g_test_add_func("/plugin/gzip-execution-trace",
			test_gzip_execution_trace);

	return g_test_run();
}
