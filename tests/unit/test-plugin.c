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
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
static qemu_plugin_vcpu_discon_cb_t discon_cb;
static enum qemu_plugin_discon_type discon_types;
#if QEMU_PLUGIN_VERSION >= 7
static void *discon_data;
#endif
#endif

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

#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
#if QEMU_PLUGIN_VERSION >= 7
void qemu_plugin_register_vcpu_discon_cb(
	qemu_plugin_id_t id, enum qemu_plugin_discon_type type,
	qemu_plugin_vcpu_discon_cb_t cb, void *userdata)
{
	discon_cb = cb;
	discon_types = type;
	discon_data = userdata;
}
#else
void qemu_plugin_register_vcpu_discon_cb(
	qemu_plugin_id_t id, enum qemu_plugin_discon_type type,
	qemu_plugin_vcpu_discon_cb_t cb)
{
	discon_cb = cb;
	discon_types = type;
}
#endif
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

#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
static void emit_discontinuity(unsigned int cpu_index,
			       enum qemu_plugin_discon_type type,
			       uint64_t from_pc, uint64_t to_pc)
{
	g_assert_nonnull(discon_cb);
	g_assert_true((discon_types & type) != 0);
#if QEMU_PLUGIN_VERSION >= 7
	discon_cb(cpu_index, type, from_pc, to_pc, discon_data);
#else
	discon_cb(1, cpu_index, type, from_pc, to_pc);
#endif
}

struct discontinuity_observation {
	unsigned int calls;
	unsigned int cpu_index;
	enum qemu_plugin_discon_type type;
	uint64_t from_pc;
	uint64_t to_pc;
};

static struct discontinuity_observation discontinuity_observation;

#if QEMU_PLUGIN_VERSION >= 7
static void observe_discontinuity(unsigned int cpu_index,
				  enum qemu_plugin_discon_type type,
				  uint64_t from_pc, uint64_t to_pc,
				  void *userdata)
#else
static void observe_discontinuity(qemu_plugin_id_t id,
				  unsigned int cpu_index,
				  enum qemu_plugin_discon_type type,
				  uint64_t from_pc, uint64_t to_pc)
#endif
{
#if QEMU_PLUGIN_VERSION >= 7
	struct discontinuity_observation *observation = userdata;
#else
	struct discontinuity_observation *observation =
		&discontinuity_observation;

	(void) id;
#endif

	observation->calls++;
	observation->cpu_index = cpu_index;
	observation->type = type;
	observation->from_pc = from_pc;
	observation->to_pc = to_pc;
}

static void test_discontinuity_callback_model(void)
{
	memset(&discontinuity_observation, 0,
	       sizeof(discontinuity_observation));
#if QEMU_PLUGIN_VERSION >= 7
	qemu_plugin_register_vcpu_discon_cb(
		1, QEMU_PLUGIN_DISCON_ALL, observe_discontinuity,
		&discontinuity_observation);
#else
	qemu_plugin_register_vcpu_discon_cb(
		1, QEMU_PLUGIN_DISCON_ALL, observe_discontinuity);
#endif

	emit_discontinuity(4, QEMU_PLUGIN_DISCON_EXCEPTION, 0x1004, 0x2000);

	g_assert_cmpuint(discontinuity_observation.calls, ==, 1);
	g_assert_cmpuint(discontinuity_observation.cpu_index, ==, 4);
	g_assert_cmpuint(discontinuity_observation.type, ==,
			 QEMU_PLUGIN_DISCON_EXCEPTION);
	g_assert_cmpuint(discontinuity_observation.from_pc, ==, 0x1004);
	g_assert_cmpuint(discontinuity_observation.to_pc, ==, 0x2000);
}
#endif

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

static void skip_trace_headers(const uint8_t **cursor)
{
	struct etrace_hdr hdr;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_INFO);
	*cursor += hdr.len;
	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_ARCH);
	*cursor += hdr.len;
}

static void assert_exec64(const uint8_t **cursor, unsigned int cpu_index,
			  uint64_t start, uint64_t end)
{
	struct etrace_entry64 entry;
	struct etrace_hdr hdr;
	uint64_t start_time;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_EXEC);
	g_assert_cmpuint(hdr.unit_id, ==, cpu_index);
	read_data(cursor, &start_time, sizeof(start_time));
	read_data(cursor, &entry, sizeof(entry));
	g_assert_cmpuint(start_time, ==, 0);
	g_assert_cmpuint(entry.duration, ==, 0);
	g_assert_cmpuint(entry.start, ==, start);
	g_assert_cmpuint(entry.end, ==, end);
}

#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
static void assert_discontinuity(const uint8_t **cursor,
				 unsigned int cpu_index, uint32_t kind,
				 uint64_t from_pc, uint64_t to_pc)
{
	struct etrace_discontinuity discontinuity;
	struct etrace_hdr hdr;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_DISCONTINUITY);
	g_assert_cmpuint(hdr.unit_id, ==, cpu_index);
	g_assert_cmpuint(hdr.len, ==, sizeof(discontinuity));
	read_data(cursor, &discontinuity, sizeof(discontinuity));
	g_assert_cmpuint(discontinuity.from_pc, ==, from_pc);
	g_assert_cmpuint(discontinuity.to_pc, ==, to_pc);
	g_assert_cmpuint(discontinuity.kind, ==, kind);
	g_assert_cmpuint(discontinuity.flags, ==, 0);
}

static void test_discontinuity_trace(void)
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
		.version = { .min = 1, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[2];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "exec=insn";

	g_assert_cmpint(qemu_plugin_install(1, &info, 2, args), ==, 0);
	g_assert_nonnull(discon_cb);
	g_assert_cmpint(discon_types, ==, QEMU_PLUGIN_DISCON_ALL);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 3, 1);
	emit_discontinuity(3, QEMU_PLUGIN_DISCON_EXCEPTION, 0x1004, 0x2000);
	emit_discontinuity(3, QEMU_PLUGIN_DISCON_INTERRUPT, 0x2004, 0x3000);
	emit_discontinuity(3, QEMU_PLUGIN_DISCON_HOSTCALL, 0x3004, 0x3008);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	skip_trace_headers(&cursor);
	assert_exec64(&cursor, 3, 0x1000, 0x1004);
	assert_discontinuity(&cursor, 3, ETRACE_DISCONTINUITY_EXCEPTION,
			     0x1004, 0x2000);
	assert_discontinuity(&cursor, 3, ETRACE_DISCONTINUITY_INTERRUPT,
			     0x2004, 0x3000);
	assert_discontinuity(&cursor, 3, ETRACE_DISCONTINUITY_HOST_CALL,
			     0x3004, 0x3008);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}
#endif

static void test_instruction_execution_trace(void)
{
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
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 1, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[2];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "exec=insn";

	g_assert_cmpint(qemu_plugin_install(1, &info, 2, args), ==, 0);
	translate_tb(&tb);
	g_assert_null(tb.exec_cb);
	g_assert_nonnull(insns[0].exec_cb);
	g_assert_nonnull(insns[1].exec_cb);
	g_assert_nonnull(insns[2].exec_cb);

	/* Model an early exit after the first instruction, then a full TB. */
	execute_tb_prefix(&tb, 5, 1);
	execute_tb_prefix(&tb, 5, tb.n_insns);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	skip_trace_headers(&cursor);
	assert_exec64(&cursor, 5, 0x1000, 0x1002);
	assert_exec64(&cursor, 5, 0x1000, 0x1002);
	assert_exec64(&cursor, 5, 0x1002, 0x1006);
	assert_exec64(&cursor, 5, 0x1006, 0x1009);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}

static void write_instruction_trace(const char *path, bool gzip)
{
	struct qemu_plugin_insn insns[] = {
		{ .vaddr = 0x4000, .size = 2 },
		{ .vaddr = 0x4002, .size = 5 },
	};
	struct qemu_plugin_tb tb = {
		.vaddr = 0x4000,
		.insns = insns,
		.n_insns = G_N_ELEMENTS(insns),
	};
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 1, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[3];
	int argc = 2;

	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "exec=insn";
	if (gzip) {
		args[2] = "compress=gzip";
		argc++;
	}

	g_assert_cmpint(qemu_plugin_install(1, &info, argc, args), ==, 0);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 6, tb.n_insns);
	finish_plugin();
	g_free(args[0]);
}

static void test_instruction_gzip_equivalence(void)
{
	uint8_t gzip_contents[512];
	char *raw_contents;
	char *gzip_path = NULL;
	char *raw_path = NULL;
	gsize raw_length;
	gzFile input;
	int gzip_length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &raw_path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(raw_path);
	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX.gz", &gzip_path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(gzip_path);

	write_instruction_trace(raw_path, false);
	write_instruction_trace(gzip_path, true);

	g_assert_true(g_file_get_contents(raw_path, &raw_contents, &raw_length,
					      NULL));
	input = gzopen(gzip_path, "rb");
	g_assert_nonnull(input);
	gzip_length = gzread(input, gzip_contents, sizeof(gzip_contents));
	g_assert_cmpint(gzip_length, >, 0);
	g_assert_cmpint(gzclose(input), ==, Z_OK);
	g_assert_cmpuint(raw_length, ==, gzip_length);
	g_assert_cmpmem(raw_contents, raw_length, gzip_contents, gzip_length);

	unlink(raw_path);
	unlink(gzip_path);
	g_free(raw_contents);
	g_free(raw_path);
	g_free(gzip_path);
}

static void test_invalid_exec_mode(void)
{
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 1, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *arg = "exec=invalid";

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, -1);
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
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
	g_test_add_func("/plugin/discontinuity-callback-model",
			test_discontinuity_callback_model);
	g_test_add_func("/plugin/discontinuity-trace",
			test_discontinuity_trace);
#endif
	g_test_add_func("/plugin/instruction-execution-trace",
			test_instruction_execution_trace);
	g_test_add_func("/plugin/instruction-gzip-equivalence",
			test_instruction_gzip_equivalence);
	g_test_add_func("/plugin/invalid-exec-mode", test_invalid_exec_mode);
	g_test_add_func("/plugin/execution-trace", test_execution_trace);
	g_test_add_func("/plugin/32bit-execution-trace",
			test_32bit_execution_trace);
	g_test_add_func("/plugin/gzip-execution-trace",
			test_gzip_execution_trace);

	return g_test_run();
}
