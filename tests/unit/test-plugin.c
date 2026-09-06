#include <fcntl.h>
#include <elf.h>
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
#if QEMU_PLUGIN_VERSION >= 2
	bool has_inline;
	enum qemu_plugin_op inline_op;
	qemu_plugin_u64 inline_entry;
	uint64_t inline_imm;
#endif
};

#if QEMU_PLUGIN_VERSION >= 2
struct qemu_plugin_register {
	const char *name;
	uint8_t value[16];
	size_t size;
	bool readable;
};

static struct qemu_plugin_register fake_registers[32];
static size_t nr_fake_registers;
#endif

struct qemu_plugin_tb {
	uint64_t vaddr;
	struct qemu_plugin_insn *insns;
	size_t n_insns;
	qemu_plugin_vcpu_udata_cb_t exec_cb;
	enum qemu_plugin_cb_flags exec_flags;
	void *exec_data;
};

#if QEMU_PLUGIN_VERSION >= 2
struct qemu_plugin_scoreboard {
	GArray *entries;
	size_t element_size;
};
#endif

static qemu_plugin_vcpu_tb_trans_cb_t trans_cb;
static qemu_plugin_udata_cb_t exit_cb;
static enum qemu_plugin_cb_flags current_callback_flags;
#if QEMU_PLUGIN_VERSION >= 7
static void *trans_data;
#endif
#if QEMU_PLUGIN_VERSION >= 2
#if QEMU_PLUGIN_VERSION >= 7
static qemu_plugin_vcpu_udata_cb_t vcpu_init_cb;
static void *vcpu_init_data;
static qemu_plugin_vcpu_udata_cb_t vcpu_exit_cb;
static void *vcpu_exit_data;
#else
static qemu_plugin_vcpu_simple_cb_t vcpu_init_cb;
static qemu_plugin_vcpu_simple_cb_t vcpu_exit_cb;
#endif
#endif
static void *exit_data;
#if QEMU_PLUGIN_VERSION >= 5
static uint64_t translate_offset;
static uint64_t translate_split_vaddr = UINT64_MAX;
static uint64_t translate_split_offset;
static uint64_t translate_fail_vaddr = UINT64_MAX;
#endif
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
static qemu_plugin_vcpu_discon_cb_t discon_cb;
static enum qemu_plugin_discon_type discon_types;
#if QEMU_PLUGIN_VERSION >= 7
static void *discon_data;
#endif
#endif

#if QEMU_PLUGIN_VERSION >= 2
#if QEMU_PLUGIN_VERSION >= 7
void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
				       qemu_plugin_vcpu_udata_cb_t cb,
				       void *userdata)
{
	vcpu_init_cb = cb;
	vcpu_init_data = userdata;
}

void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
				       qemu_plugin_vcpu_udata_cb_t cb,
				       void *userdata)
{
	vcpu_exit_cb = cb;
	vcpu_exit_data = userdata;
}
#else
void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
				       qemu_plugin_vcpu_simple_cb_t cb)
{
	vcpu_init_cb = cb;
}

void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
				       qemu_plugin_vcpu_simple_cb_t cb)
{
	vcpu_exit_cb = cb;
}
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
	tb->exec_flags = flags;
	tb->exec_data = userdata;
}

void qemu_plugin_register_vcpu_insn_exec_cb(
	struct qemu_plugin_insn *insn, qemu_plugin_vcpu_udata_cb_t cb,
	enum qemu_plugin_cb_flags flags, void *userdata)
{
	insn->exec_cb = cb;
	insn->exec_data = userdata;
}

#if QEMU_PLUGIN_VERSION >= 2
void qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
	struct qemu_plugin_insn *insn, enum qemu_plugin_op op,
	qemu_plugin_u64 entry, uint64_t imm)
{
	insn->has_inline = true;
	insn->inline_op = op;
	insn->inline_entry = entry;
	insn->inline_imm = imm;
}

struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size)
{
	struct qemu_plugin_scoreboard *score;

	score = g_new(struct qemu_plugin_scoreboard, 1);
	score->entries = g_array_new(false, true, element_size);
	score->element_size = element_size;
	return score;
}

void qemu_plugin_scoreboard_free(struct qemu_plugin_scoreboard *score)
{
	g_array_free(score->entries, true);
	g_free(score);
}

void *qemu_plugin_scoreboard_find(struct qemu_plugin_scoreboard *score,
				  unsigned int cpu_index)
{
	if (score->entries->len <= cpu_index)
		g_array_set_size(score->entries, cpu_index + 1);
	return (uint8_t *)score->entries->data + cpu_index * score->element_size;
}

uint64_t qemu_plugin_u64_get(qemu_plugin_u64 entry,
			     unsigned int cpu_index)
{
	uint8_t *element = qemu_plugin_scoreboard_find(entry.score, cpu_index);

	return *(uint64_t *)(element + entry.offset);
}

void qemu_plugin_u64_set(qemu_plugin_u64 entry, unsigned int cpu_index,
			 uint64_t value)
{
	uint8_t *element = qemu_plugin_scoreboard_find(entry.score, cpu_index);

	*(uint64_t *)(element + entry.offset) = value;
}
#endif

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

#if QEMU_PLUGIN_VERSION >= 2
GArray *qemu_plugin_get_registers(void)
{
	GArray *descriptors = g_array_new(false, true,
					  sizeof(qemu_plugin_reg_descriptor));
	size_t i;

	for (i = 0; i < nr_fake_registers; i++) {
		qemu_plugin_reg_descriptor descriptor = {
			.handle = &fake_registers[i],
			.name = fake_registers[i].name,
			.feature = "test",
		};

		g_array_append_val(descriptors, descriptor);
	}
	return descriptors;
}

#if QEMU_PLUGIN_VERSION >= 6
bool qemu_plugin_read_register(struct qemu_plugin_register *handle,
			       GByteArray *buf)
#else
int qemu_plugin_read_register(struct qemu_plugin_register *handle,
			      GByteArray *buf)
#endif
{
	if (!handle->readable || current_callback_flags == QEMU_PLUGIN_CB_NO_REGS)
		return false;
	g_byte_array_append(buf, handle->value, handle->size);
#if QEMU_PLUGIN_VERSION >= 6
	return true;
#else
	return handle->size;
#endif
}

static void clear_fake_registers(void)
{
	memset(fake_registers, 0, sizeof(fake_registers));
	nr_fake_registers = 0;
}

static struct qemu_plugin_register *add_fake_register(const char *name,
						      uint64_t value,
						      size_t size)
{
	struct qemu_plugin_register *reg;
	size_t i;

	g_assert_cmpuint(nr_fake_registers, <, G_N_ELEMENTS(fake_registers));
	g_assert_cmpuint(size, <=, sizeof(reg->value));
	reg = &fake_registers[nr_fake_registers++];
	reg->name = name;
	reg->size = size;
	reg->readable = true;
	for (i = 0; i < size; i++)
		reg->value[i] = i < sizeof(value) ? value >> (i * 8) : 0;
	return reg;
}

static void initialize_vcpu(unsigned int cpu_index)
{
	g_assert_nonnull(vcpu_init_cb);
#if QEMU_PLUGIN_VERSION >= 7
	vcpu_init_cb(cpu_index, vcpu_init_data);
#else
	vcpu_init_cb(1, cpu_index);
#endif
}
#endif

#if QEMU_PLUGIN_VERSION >= 5
bool qemu_plugin_translate_vaddr(uint64_t vaddr, uint64_t *hwaddr)
{
	if (vaddr == translate_fail_vaddr)
		return false;
	*hwaddr = vaddr + (vaddr >= translate_split_vaddr
		? translate_split_offset : translate_offset);
	return true;
}
#endif

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
	if (tb->exec_cb) {
		current_callback_flags = tb->exec_flags;
		tb->exec_cb(cpu_index, tb->exec_data);
		current_callback_flags = QEMU_PLUGIN_CB_NO_REGS;
	}
	for (i = 0; i < n_insns; i++) {
		struct qemu_plugin_insn *insn = &tb->insns[i];

#if QEMU_PLUGIN_VERSION >= 2
		if (insn->has_inline) {
			uint64_t value = qemu_plugin_u64_get(insn->inline_entry,
							 cpu_index);

#if QEMU_PLUGIN_VERSION >= 3
			if (insn->inline_op == QEMU_PLUGIN_INLINE_STORE_U64)
				value = insn->inline_imm;
			else
#endif
				value += insn->inline_imm;
			qemu_plugin_u64_set(insn->inline_entry, cpu_index, value);
		}
#endif
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

#if QEMU_PLUGIN_VERSION >= 2
static void exit_vcpu(unsigned int cpu_index)
{
	g_assert_nonnull(vcpu_exit_cb);
#if QEMU_PLUGIN_VERSION >= 7
	vcpu_exit_cb(cpu_index, vcpu_exit_data);
#else
	vcpu_exit_cb(1, cpu_index);
#endif
}
#endif

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

#if QEMU_PLUGIN_VERSION >= 3
struct scoreboard_entry {
	uint64_t reached_last;
};

static void test_scoreboard_inline_store_model(void)
{
	struct qemu_plugin_insn insns[] = {
		{ .vaddr = 0x1000, .size = 4 },
		{ .vaddr = 0x1004, .size = 4 },
		{ .vaddr = 0x1008, .size = 4 },
	};
	struct qemu_plugin_tb tb = {
		.vaddr = 0x1000,
		.insns = insns,
		.n_insns = G_N_ELEMENTS(insns),
	};
	struct qemu_plugin_scoreboard *score;
	qemu_plugin_u64 reached_last;

	score = qemu_plugin_scoreboard_new(sizeof(struct scoreboard_entry));
	reached_last = qemu_plugin_scoreboard_u64_in_struct(
		score, struct scoreboard_entry, reached_last);
	qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
		&insns[2], QEMU_PLUGIN_INLINE_STORE_U64, reached_last, 1);

	execute_tb_prefix(&tb, 1, 2);
	g_assert_cmpuint(qemu_plugin_u64_get(reached_last, 1), ==, 0);
	execute_tb_prefix(&tb, 1, tb.n_insns);
	g_assert_cmpuint(qemu_plugin_u64_get(reached_last, 1), ==, 1);
	g_assert_cmpuint(qemu_plugin_u64_get(reached_last, 2), ==, 0);

	qemu_plugin_scoreboard_free(score);
}
#endif

static void read_data(const uint8_t **cursor, void *value, size_t size)
{
	memcpy(value, *cursor, size);
	*cursor += size;
}

static uint64_t read_trace_headers_version(const uint8_t **cursor,
					   uint16_t *major)
{
	struct etrace_info_data info;
	struct etrace_hdr hdr;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_INFO);
	g_assert_cmpuint(hdr.len, >=, sizeof(info));
	read_data(cursor, &info, sizeof(info));
	if (major)
		*major = info.version.major;
	*cursor += hdr.len - sizeof(info);
	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_ARCH);
	*cursor += hdr.len;
	return info.attr;
}

static uint64_t read_trace_headers(const uint8_t **cursor)
{
	return read_trace_headers_version(cursor, NULL);
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

#if QEMU_PLUGIN_VERSION >= 2
static void assert_tb_definition(const uint8_t **cursor, uint64_t tb_id,
				 uint64_t vaddr, uint64_t context_id,
				 const struct qemu_plugin_insn *expected,
				 size_t n_insns,
				 const struct etrace_tb_mapping *expected_mappings,
				 size_t n_mappings)
{
	struct etrace_tb_def definition;
	struct etrace_tb_insn insn;
	struct etrace_hdr hdr;
	size_t i;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_TB_DEF);
	g_assert_cmpuint(hdr.len, ==,
			 offsetof(struct etrace_tb_def, data8)
			 + n_insns * sizeof(insn)
			 + n_mappings * sizeof(*expected_mappings));
	read_data(cursor, &definition, offsetof(struct etrace_tb_def, data8));
	g_assert_cmpuint(definition.tb_id, ==, tb_id);
	g_assert_cmpuint(definition.vaddr, ==, vaddr);
	g_assert_cmpuint(definition.context_id, ==, context_id);
	g_assert_cmpuint(definition.size, ==,
			 expected[n_insns - 1].vaddr + expected[n_insns - 1].size
			 - vaddr);
	g_assert_cmpuint(definition.insn_count, ==, n_insns);
	g_assert_cmpuint(definition.mapping_count, ==, n_mappings);
	g_assert_cmpuint(definition.code_len, ==, 0);
	for (i = 0; i < n_insns; i++) {
		read_data(cursor, &insn, sizeof(insn));
		g_assert_cmpuint(insn.offset, ==, expected[i].vaddr - vaddr);
		g_assert_cmpuint(insn.size, ==, expected[i].size);
	}
	for (i = 0; i < n_mappings; i++) {
		struct etrace_tb_mapping mapping;

		read_data(cursor, &mapping, sizeof(mapping));
		g_assert_cmpuint(mapping.offset, ==, expected_mappings[i].offset);
		g_assert_cmpuint(mapping.len, ==, expected_mappings[i].len);
		g_assert_cmpuint(mapping.paddr, ==, expected_mappings[i].paddr);
	}
}

static void assert_context(const uint8_t **cursor, unsigned int cpu_index,
			   uint64_t context_id, uint32_t flags)
{
	struct etrace_context context;
	struct etrace_hdr hdr;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_CONTEXT);
	g_assert_cmpuint(hdr.unit_id, ==, cpu_index);
	g_assert_cmpuint(hdr.len, ==, sizeof(context));
	read_data(cursor, &context, sizeof(context));
	g_assert_cmpuint(context.context_id, ==, context_id);
	g_assert_cmpuint(context.flags, ==, flags);
	g_assert_cmpuint(context.register_count, ==, 0);
}

struct expected_context_register {
	const char *name;
	uint64_t value;
	size_t size;
};

static void assert_context_registers(
	const uint8_t **cursor, unsigned int cpu_index, uint64_t context_id,
	uint64_t address_space_id, uint8_t privilege, uint32_t flags,
	const struct expected_context_register *expected, size_t n_registers)
{
	struct etrace_context context;
	struct etrace_hdr hdr;
	const uint8_t *payload;
	size_t i;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_CONTEXT);
	g_assert_cmpuint(hdr.unit_id, ==, cpu_index);
	payload = *cursor;
	read_data(cursor, &context, sizeof(context));
	g_assert_cmpuint(context.context_id, ==, context_id);
	g_assert_cmpuint(context.address_space_id, ==, address_space_id);
	g_assert_cmpuint(context.privilege, ==, privilege);
	g_assert_cmpuint(context.flags, ==, flags);
	g_assert_cmpuint(context.architecture, ==, EM_X86_64);
	g_assert_cmpuint(context.register_count, ==, n_registers);
	g_assert_cmpuint(context.state_hash, !=, 0);
	for (i = 0; i < n_registers; i++) {
		struct etrace_context_register reg;
		uint8_t *value;
		uint64_t decoded = 0;
		size_t j;

		read_data(cursor, &reg, sizeof(reg));
		g_assert_cmpuint(reg.name_len, ==, strlen(expected[i].name));
		g_assert_cmpuint(reg.size, ==, expected[i].size);
		g_assert_cmpmem(*cursor, reg.name_len,
				expected[i].name, strlen(expected[i].name));
		*cursor += reg.name_len;
		value = g_malloc(reg.size);
		read_data(cursor, value, reg.size);
		for (j = 0; j < reg.size && j < sizeof(decoded); j++)
			decoded |= (uint64_t)value[j] << (j * 8);
		g_assert_cmpuint(decoded, ==, expected[i].value);
		g_free(value);
	}
	g_assert_cmpuint(hdr.len, ==, (size_t)(*cursor - payload));
}

static void assert_context_gap(const uint8_t **cursor,
			       unsigned int cpu_index, uint64_t sequence,
			       uint64_t from_context_id,
			       uint64_t to_context_id,
			       uint64_t filtered_execs)
{
	struct etrace_context_gap gap;
	struct etrace_hdr hdr;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_CONTEXT_GAP);
	g_assert_cmpuint(hdr.unit_id, ==, cpu_index);
	g_assert_cmpuint(hdr.len, ==, sizeof(gap));
	read_data(cursor, &gap, sizeof(gap));
	g_assert_cmpuint(gap.sequence, ==, sequence);
	g_assert_cmpuint(gap.from_context_id, ==, from_context_id);
	g_assert_cmpuint(gap.to_context_id, ==, to_context_id);
	g_assert_cmpuint(gap.filtered_execs, ==, filtered_execs);
	g_assert_cmpuint(gap.reason, ==, ETRACE_CONTEXT_GAP_FILTERED);
}

static void assert_tb_execution(const uint8_t **cursor,
				unsigned int cpu_index, uint64_t sequence,
				uint64_t tb_id, uint64_t context_id,
				uint16_t insn_count)
{
	struct etrace_tb_exec execution;
	struct etrace_hdr hdr;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_TB_EXEC);
	g_assert_cmpuint(hdr.unit_id, ==, cpu_index);
	g_assert_cmpuint(hdr.len, ==, sizeof(execution));
	read_data(cursor, &execution, sizeof(execution));
	g_assert_cmpuint(execution.sequence, ==, sequence);
	g_assert_cmpuint(execution.tb_id, ==, tb_id);
	g_assert_cmpuint(execution.context_id, ==, context_id);
	g_assert_cmpuint(execution.insn_count, ==, insn_count);
}
#endif

static struct etrace_status read_status(const uint8_t **cursor)
{
	struct etrace_status status;
	struct etrace_hdr hdr;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_STATUS);
	g_assert_cmpuint(hdr.len, ==, sizeof(status));
	read_data(cursor, &status, sizeof(status));
	g_assert_cmpuint(status.flags, ==, ETRACE_STATUS_F_COMPLETE);
	return status;
}

#if QEMU_PLUGIN_VERSION >= 2
static struct etrace_status_v1 read_status_v1(const uint8_t **cursor)
{
	struct etrace_status_v1 status;
	struct etrace_hdr hdr;

	read_data(cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_STATUS);
	g_assert_cmpuint(hdr.len, ==, sizeof(status));
	read_data(cursor, &status, sizeof(status));
	return status;
}
#endif

static void assert_status(const uint8_t **cursor,
			  uint64_t discontinuity_pc_mismatches)
{
	struct etrace_status status = read_status(cursor);

	g_assert_cmpuint(status.unresolved_tb_exits, ==, 0);
	g_assert_cmpuint(status.unresolved_discontinuities, ==, 0);
	g_assert_cmpuint(status.unresolved_vcpu_exits, ==, 0);
	g_assert_cmpuint(status.output_errors, ==, 0);
	g_assert_cmpuint(status.discontinuity_pc_mismatches, ==,
			discontinuity_pc_mismatches);
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
	char *arg;
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	arg = g_strdup_printf("out=%s", path);

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, 0);
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
	g_assert_cmpuint(read_trace_headers(&cursor), ==,
			 ETRACE_INFO_F_FINAL_STATUS);
	assert_exec64(&cursor, 3, 0x1000, 0x1004);
	assert_discontinuity(&cursor, 3, ETRACE_DISCONTINUITY_EXCEPTION,
			     0x1004, 0x2000);
	assert_discontinuity(&cursor, 3, ETRACE_DISCONTINUITY_INTERRUPT,
			     0x2004, 0x3000);
	assert_discontinuity(&cursor, 3, ETRACE_DISCONTINUITY_HOST_CALL,
			     0x3004, 0x3008);
	assert_status(&cursor, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}
#endif

#if QEMU_PLUGIN_VERSION < 2
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
	char *arg;
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	arg = g_strdup_printf("out=%s", path);

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, 0);
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
	g_assert_cmpuint(read_trace_headers(&cursor), ==,
			 ETRACE_INFO_F_FINAL_STATUS);
	assert_exec64(&cursor, 5, 0x1000, 0x1002);
	assert_exec64(&cursor, 5, 0x1000, 0x1002);
	assert_exec64(&cursor, 5, 0x1002, 0x1006);
	assert_exec64(&cursor, 5, 0x1006, 0x1009);
	assert_status(&cursor, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}
#endif

static void write_execution_trace(const char *path, bool gzip)
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
	char *args[2];
	int argc = 1;

	args[0] = g_strdup_printf("out=%s", path);
	if (gzip) {
		args[1] = "compress=gzip";
		argc++;
	}

	g_assert_cmpint(qemu_plugin_install(1, &info, argc, args), ==, 0);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 6, tb.n_insns);
#if QEMU_PLUGIN_VERSION >= 2
	exit_vcpu(6);
#endif
	finish_plugin();
	g_free(args[0]);
}

static void test_gzip_equivalence(void)
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

	write_execution_trace(raw_path, false);
	write_execution_trace(gzip_path, true);

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

static void test_invalid_option(void)
{
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 1, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *arg = "invalid";

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, -1);
}

#if QEMU_PLUGIN_VERSION >= 2
static void test_accurate_execution_trace(void)
{
	struct qemu_plugin_insn first_insns[] = {
		{ .vaddr = 0x1000, .size = 4 },
		{ .vaddr = 0x1004, .size = 4 },
		{ .vaddr = 0x1008, .size = 4 },
	};
	struct qemu_plugin_insn second_insns[] = {
		{ .vaddr = 0x2000, .size = 4 },
		{ .vaddr = 0x2004, .size = 4 },
		{ .vaddr = 0x2008, .size = 4 },
	};
	struct qemu_plugin_tb first = {
		.vaddr = 0x1000,
		.insns = first_insns,
		.n_insns = G_N_ELEMENTS(first_insns),
	};
	struct qemu_plugin_tb second = {
		.vaddr = 0x2000,
		.insns = second_insns,
		.n_insns = G_N_ELEMENTS(second_insns),
	};
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *arg;
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	arg = g_strdup_printf("out=%s", path);

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, 0);
	g_assert_nonnull(vcpu_exit_cb);
	translate_tb(&first);
	translate_tb(&second);

	g_assert_true(first_insns[0].has_inline);
	g_assert_true(first_insns[1].has_inline);
	g_assert_true(first_insns[2].has_inline);
	g_assert_true(second_insns[0].has_inline);
	g_assert_true(second_insns[1].has_inline);
	g_assert_true(second_insns[2].has_inline);

	execute_tb_prefix(&first, 2, first.n_insns);
	execute_tb_prefix(&second, 2, 1);
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
	emit_discontinuity(2, QEMU_PLUGIN_DISCON_EXCEPTION, 0x41a7f1, 0x3000);
#endif
	exit_vcpu(2);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	g_assert_cmpuint(read_trace_headers(&cursor), ==,
			 ETRACE_INFO_F_FINAL_STATUS);
	assert_exec64(&cursor, 2, 0x1000, 0x100c);
	assert_exec64(&cursor, 2, 0x2000, 0x2004);
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
	assert_discontinuity(&cursor, 2, ETRACE_DISCONTINUITY_EXCEPTION,
			     0x41a7f1, 0x3000);
	assert_status(&cursor, 1);
#else
	assert_status(&cursor, 0);
#endif
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}

#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
static void test_unreported_system_transition(void)
{
	struct qemu_plugin_insn guest_insns[] = {
		{ .vaddr = 0x41a807, .size = 3 },
		{ .vaddr = 0x41a80a, .size = 6 },
		{ .vaddr = 0x41a810, .size = 5 },
	};
	struct qemu_plugin_insn host_insns[] = {
		{ .vaddr = UINT64_C(0xffff82d0402a4aab), .size = 4 },
		{ .vaddr = UINT64_C(0xffff82d0402a4aaf), .size = 3 },
	};
	struct qemu_plugin_tb guest = {
		.vaddr = 0x41a807,
		.insns = guest_insns,
		.n_insns = G_N_ELEMENTS(guest_insns),
	};
	struct qemu_plugin_tb host = {
		.vaddr = UINT64_C(0xffff82d0402a4aab),
		.insns = host_insns,
		.n_insns = G_N_ELEMENTS(host_insns),
	};
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *arg;
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	unsigned int i;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	arg = g_strdup_printf("out=%s", path);

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, 0);
	translate_tb(&guest);
	translate_tb(&host);
	for (i = 0; i < 2; i++) {
		execute_tb_prefix(&guest, 3, 2);
		execute_tb_prefix(&host, 3, host.n_insns);
	}
	exit_vcpu(3);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	g_assert_cmpuint(read_trace_headers(&cursor), ==,
			 ETRACE_INFO_F_FINAL_STATUS);
	for (i = 0; i < 2; i++) {
		assert_exec64(&cursor, 3, 0x41a807, 0x41a810);
		assert_exec64(&cursor, 3, UINT64_C(0xffff82d0402a4aab),
			      UINT64_C(0xffff82d0402a4ab2));
	}
	assert_status(&cursor, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}

static void test_accurate_internal_restart(void)
{
	struct qemu_plugin_insn original_insns[] = {
		{ .vaddr = 0x1000, .size = 4 },
		{ .vaddr = 0x1004, .size = 4 },
		{ .vaddr = 0x1008, .size = 4 },
	};
	struct qemu_plugin_insn restart_insns[] = {
		{ .vaddr = 0x1004, .size = 4 },
		{ .vaddr = 0x1008, .size = 4 },
	};
	struct qemu_plugin_tb original = {
		.vaddr = 0x1000,
		.insns = original_insns,
		.n_insns = G_N_ELEMENTS(original_insns),
	};
	struct qemu_plugin_tb restart = {
		.vaddr = 0x1004,
		.insns = restart_insns,
		.n_insns = G_N_ELEMENTS(restart_insns),
	};
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *arg;
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	arg = g_strdup_printf("out=%s", path);

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, 0);
	translate_tb(&original);
	translate_tb(&restart);
	execute_tb_prefix(&original, 1, 1);
	execute_tb_prefix(&restart, 1, restart.n_insns);
	exit_vcpu(1);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	g_assert_cmpuint(read_trace_headers(&cursor), ==,
			 ETRACE_INFO_F_FINAL_STATUS);
	assert_exec64(&cursor, 1, 0x1000, 0x1004);
	assert_exec64(&cursor, 1, 0x1004, 0x100c);
	assert_status(&cursor, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}
#endif
#endif

#if QEMU_PLUGIN_VERSION >= 2
static void test_tb_execution_trace(void)
{
	struct qemu_plugin_insn insns[] = {
		{ .vaddr = 0x5000, .size = 2 },
		{ .vaddr = 0x5002, .size = 5 },
		{ .vaddr = 0x5007, .size = 3 },
	};
	struct qemu_plugin_tb tb = {
		.vaddr = 0x5000,
		.insns = insns,
		.n_insns = G_N_ELEMENTS(insns),
	};
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[2];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	uint16_t major;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "format=v1";

	g_assert_cmpint(qemu_plugin_install(1, &info, 2, args), ==, 0);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 2, 2);
	execute_tb_prefix(&tb, 2, tb.n_insns);
	exit_vcpu(2);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	g_assert_cmpuint(read_trace_headers_version(&cursor, &major), ==,
			 ETRACE_INFO_F_FINAL_STATUS | ETRACE_INFO_F_TB_EXEC);
	g_assert_cmpuint(major, ==, ETRACE_VERSION_TB_EXEC);
	assert_tb_definition(&cursor, 1, 0x5000, 0, insns,
			     G_N_ELEMENTS(insns), NULL, 0);
	assert_tb_execution(&cursor, 2, 1, 1, 0, 2);
	assert_tb_execution(&cursor, 2, 2, 1, 0, 3);
	{
		struct etrace_status_v1 status = read_status_v1(&cursor);

		g_assert_cmpuint(status.base.flags, ==, ETRACE_STATUS_F_COMPLETE);
		g_assert_cmpuint(status.filtered_execs, ==, 0);
		g_assert_cmpuint(status.context_errors, ==, 0);
		g_assert_cmpuint(status.mapping_errors, ==, 0);
	}
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}

static void test_hypervisor_filter(void)
{
	struct qemu_plugin_insn first_insns[] = {
		{ .vaddr = 0x1000, .size = 4 },
		{ .vaddr = 0x1004, .size = 4 },
	};
	struct qemu_plugin_insn guest_insns[] = {
		{ .vaddr = 0x2000, .size = 4 },
		{ .vaddr = 0x2004, .size = 4 },
	};
	struct qemu_plugin_insn second_insns[] = {
		{ .vaddr = 0x1080, .size = 4 },
	};
	struct qemu_plugin_tb first = {
		.vaddr = 0x1000,
		.insns = first_insns,
		.n_insns = G_N_ELEMENTS(first_insns),
	};
	struct qemu_plugin_tb guest = {
		.vaddr = 0x2000,
		.insns = guest_insns,
		.n_insns = G_N_ELEMENTS(guest_insns),
	};
	struct qemu_plugin_tb second = {
		.vaddr = 0x1080,
		.insns = second_insns,
		.n_insns = G_N_ELEMENTS(second_insns),
	};
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[4];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	struct etrace_status_v1 status;
	gsize length;
	uint16_t major;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "format=v1";
	args[2] = "context=hypervisor";
	args[3] = "context-range=0x1000:0x100";

	g_assert_cmpint(qemu_plugin_install(1, &info, 4, args), ==, 0);
	translate_tb(&first);
	translate_tb(&guest);
	translate_tb(&second);
	execute_tb_prefix(&first, 3, first.n_insns);
	execute_tb_prefix(&guest, 3, guest.n_insns);
	execute_tb_prefix(&guest, 3, 1);
	execute_tb_prefix(&second, 3, second.n_insns);
	exit_vcpu(3);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	g_assert_cmpuint(read_trace_headers_version(&cursor, &major), ==,
			 ETRACE_INFO_F_FINAL_STATUS | ETRACE_INFO_F_TB_EXEC
			 | ETRACE_INFO_F_CONTEXT | ETRACE_INFO_F_FILTERED);
	g_assert_cmpuint(major, ==, ETRACE_VERSION_TB_EXEC);
	assert_tb_definition(&cursor, 1, 0x1000, 0, first_insns,
			     G_N_ELEMENTS(first_insns), NULL, 0);
	assert_tb_definition(&cursor, 3, 0x1080, 0, second_insns,
			     G_N_ELEMENTS(second_insns), NULL, 0);
	assert_context(&cursor, 3, 1, ETRACE_CONTEXT_F_HYPERVISOR);
	assert_context(&cursor, 3, 2, 0);
	assert_tb_execution(&cursor, 3, 1, 1, 1, 2);
	assert_context(&cursor, 3, 3, ETRACE_CONTEXT_F_HYPERVISOR);
	assert_context_gap(&cursor, 3, 2, 1, 3, 2);
	assert_tb_execution(&cursor, 3, 3, 3, 3, 1);
	status = read_status_v1(&cursor);
	g_assert_cmpuint(status.base.flags, ==, ETRACE_STATUS_F_COMPLETE);
	g_assert_cmpuint(status.filtered_execs, ==, 2);
	g_assert_cmpuint(status.context_errors, ==, 0);
	g_assert_cmpuint(status.mapping_errors, ==, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}

static void test_context_filter_options(void)
{
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *missing_format[] = {
		"context=hypervisor", "context-range=0x1000:0x100",
	};
	char *missing_range[] = { "format=v1", "context=hypervisor" };
	char *orphan_range[] = { "format=v1", "context-range=0x1000:0x100" };
	char *invalid_range[] = {
		"format=v1", "context=hypervisor", "context-range=broken",
	};

	g_assert_cmpint(qemu_plugin_install(1, &info, 2, missing_format), ==, -1);
	g_assert_cmpint(qemu_plugin_install(1, &info, 2, missing_range), ==, -1);
	g_assert_cmpint(qemu_plugin_install(1, &info, 2, orphan_range), ==, -1);
	g_assert_cmpint(qemu_plugin_install(1, &info, 3, invalid_range), ==, -1);
}

static void test_hypervisor_filter_rejects_partial_tb(void)
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
		.target_name = "x86_64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[4];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	struct etrace_status_v1 status;
	gsize length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "format=v1";
	args[2] = "context=hypervisor";
	args[3] = "context-range=0x1000:4";

	g_assert_cmpint(qemu_plugin_install(1, &info, 4, args), ==, 0);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 1, tb.n_insns);
	exit_vcpu(1);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	read_trace_headers(&cursor);
	assert_context(&cursor, 1, 1, 0);
	assert_context_gap(&cursor, 1, 1, 0, 0, 1);
	status = read_status_v1(&cursor);
	g_assert_cmpuint(status.context_errors, ==, 1);
	g_assert_cmpuint(status.filtered_execs, ==, 1);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}

static void test_register_context_changes(void)
{
	struct qemu_plugin_insn insn = { .vaddr = 0x8000, .size = 4 };
	struct qemu_plugin_tb tb = {
		.vaddr = 0x8000,
		.insns = &insn,
		.n_insns = 1,
	};
	struct qemu_plugin_register *cr3;
	struct expected_context_register first[] = {
		{ "cs", 3, 4 },
		{ "eflags", 2, 4 },
		{ "cr0", UINT64_C(1) << 31, 8 },
		{ "cr3", 0x123000, 8 },
		{ "cr4", 0x20, 8 },
		{ "efer", UINT64_C(1) << 10, 8 },
	};
	struct expected_context_register second[G_N_ELEMENTS(first)];
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[3];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	struct etrace_status_v1 status;
	gsize length;
	int fd;

	clear_fake_registers();
	add_fake_register("cs", 3, 4);
	add_fake_register("eflags", 2, 4);
	add_fake_register("cr0", UINT64_C(1) << 31, 8);
	cr3 = add_fake_register("cr3", 0x123000, 8);
	add_fake_register("cr4", 0x20, 8);
	add_fake_register("efer", UINT64_C(1) << 10, 8);
	memcpy(second, first, sizeof(second));
	second[3].value = 0x456000;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "format=v1";
	args[2] = "context-registers=basic";

	g_assert_cmpint(qemu_plugin_install(1, &info, 3, args), ==, 0);
	initialize_vcpu(1);
	translate_tb(&tb);
	g_assert_cmpint(tb.exec_flags, ==, QEMU_PLUGIN_CB_R_REGS);
	execute_tb_prefix(&tb, 1, 1);
	execute_tb_prefix(&tb, 1, 1);
	cr3->value[1] = 0x60;
	cr3->value[2] = 0x45;
	execute_tb_prefix(&tb, 1, 1);
	exit_vcpu(1);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	g_assert_cmpuint(read_trace_headers(&cursor), ==,
			 ETRACE_INFO_F_FINAL_STATUS | ETRACE_INFO_F_TB_EXEC
			 | ETRACE_INFO_F_CONTEXT);
	assert_tb_definition(&cursor, 1, 0x8000, 0, &insn, 1, NULL, 0);
	assert_context_registers(
		&cursor, 1, 1, 0x123000, 3,
		ETRACE_CONTEXT_F_PRIVILEGE_VALID
			| ETRACE_CONTEXT_F_ADDRESS_SPACE_VALID
			| ETRACE_CONTEXT_F_PAGING | ETRACE_CONTEXT_F_LONG_MODE,
		first, G_N_ELEMENTS(first));
	assert_tb_execution(&cursor, 1, 1, 1, 1, 1);
	assert_context_registers(
		&cursor, 1, 2, 0x456000, 3,
		ETRACE_CONTEXT_F_PRIVILEGE_VALID
			| ETRACE_CONTEXT_F_ADDRESS_SPACE_VALID
			| ETRACE_CONTEXT_F_PAGING | ETRACE_CONTEXT_F_LONG_MODE,
		second, G_N_ELEMENTS(second));
	assert_tb_execution(&cursor, 1, 2, 1, 1, 1);
	assert_tb_execution(&cursor, 1, 3, 1, 2, 1);
	status = read_status_v1(&cursor);
	g_assert_cmpuint(status.context_errors, ==, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}

static void test_context_register_options(void)
{
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *missing_format[] = { "context-registers=cr3" };
	char *duplicate[] = {
		"format=v1", "context-register=cr3", "context-register=cr3",
	};
	char *empty[] = { "format=v1", "context-register=" };

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, missing_format), ==, -1);
	g_assert_cmpint(qemu_plugin_install(1, &info, 3, duplicate), ==, -1);
	g_assert_cmpint(qemu_plugin_install(1, &info, 2, empty), ==, -1);
}

static void test_missing_context_register(void)
{
	struct qemu_plugin_insn insn = { .vaddr = 0x9000, .size = 4 };
	struct qemu_plugin_tb tb = {
		.vaddr = 0x9000,
		.insns = &insn,
		.n_insns = 1,
	};
	const struct expected_context_register expected[] = {
		{ "cr3", 0xabc000, 8 },
	};
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[4];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	struct etrace_status_v1 status;
	gsize length;
	int fd;

	clear_fake_registers();
	add_fake_register("cr3", 0xabc000, 8);
	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "format=v1";
	args[2] = "context-register=cr3";
	args[3] = "context-register=missing";

	g_assert_cmpint(qemu_plugin_install(1, &info, 4, args), ==, 0);
	initialize_vcpu(2);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 2, 1);
	exit_vcpu(2);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	read_trace_headers(&cursor);
	assert_tb_definition(&cursor, 1, 0x9000, 0, &insn, 1, NULL, 0);
	assert_context_registers(
		&cursor, 2, 1, 0xabc000, UINT8_MAX,
		ETRACE_CONTEXT_F_ADDRESS_SPACE_VALID
			| ETRACE_CONTEXT_F_INCOMPLETE,
		expected, G_N_ELEMENTS(expected));
	assert_tb_execution(&cursor, 2, 1, 1, 1, 1);
	status = read_status_v1(&cursor);
	g_assert_cmpuint(status.context_errors, ==, 1);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}

#if QEMU_PLUGIN_VERSION >= 5
static void test_execution_mappings(void)
{
	struct qemu_plugin_insn insns[] = {
		{ .vaddr = 0x6000, .size = 4 },
		{ .vaddr = 0x6004, .size = 4 },
	};
	struct qemu_plugin_tb tb = {
		.vaddr = 0x6000,
		.insns = insns,
		.n_insns = G_N_ELEMENTS(insns),
	};
	const struct etrace_tb_mapping mappings[] = {
		{ .offset = 0, .len = 4, .paddr = 0x16000 },
		{ .offset = 4, .len = 4, .paddr = 0x26004 },
	};
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 5, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[3];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	struct etrace_status_v1 status;
	gsize length;
	int fd;

	translate_offset = 0x10000;
	translate_split_vaddr = 0x6004;
	translate_split_offset = 0x20000;
	translate_fail_vaddr = UINT64_MAX;
	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "format=v1";
	args[2] = "exec-mapping=on";

	g_assert_cmpint(qemu_plugin_install(1, &info, 3, args), ==, 0);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 1, tb.n_insns);
	exit_vcpu(1);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	g_assert_cmpuint(read_trace_headers(&cursor), ==,
			 ETRACE_INFO_F_FINAL_STATUS | ETRACE_INFO_F_TB_EXEC
			 | ETRACE_INFO_F_EXEC_MAPPING);
	assert_tb_definition(&cursor, 1, 0x6000, 0, insns,
			     G_N_ELEMENTS(insns), mappings,
			     G_N_ELEMENTS(mappings));
	assert_tb_execution(&cursor, 1, 1, 1, 0, 2);
	status = read_status_v1(&cursor);
	g_assert_cmpuint(status.mapping_errors, ==, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	translate_offset = 0;
	translate_split_vaddr = UINT64_MAX;
	translate_split_offset = 0;
	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}

static void test_execution_mapping_failure(void)
{
	struct qemu_plugin_insn insn = { .vaddr = 0x7000, .size = 4 };
	struct qemu_plugin_tb tb = {
		.vaddr = 0x7000,
		.insns = &insn,
		.n_insns = 1,
	};
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 5, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[3];
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	struct etrace_status_v1 status;
	gsize length;
	int fd;

	translate_fail_vaddr = 0x7000;
	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	args[0] = g_strdup_printf("out=%s", path);
	args[1] = "format=v1";
	args[2] = "exec-mapping=on";

	g_assert_cmpint(qemu_plugin_install(1, &info, 3, args), ==, 0);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 1, 1);
	exit_vcpu(1);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	read_trace_headers(&cursor);
	assert_tb_definition(&cursor, 1, 0x7000, 0, &insn, 1, NULL, 0);
	assert_tb_execution(&cursor, 1, 1, 1, 0, 1);
	status = read_status_v1(&cursor);
	g_assert_cmpuint(status.mapping_errors, ==, 1);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	translate_fail_vaddr = UINT64_MAX;
	unlink(path);
	g_free(contents);
	g_free(args[0]);
	g_free(path);
}

static void test_execution_mapping_requires_v1(void)
{
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 5, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *arg = "exec-mapping=on";

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, -1);
}

static void test_execution_mapping_requires_system_emulation(void)
{
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 5, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = false,
	};
	char *args[] = { "format=v1", "exec-mapping=on" };

	g_assert_cmpint(qemu_plugin_install(1, &info, 2, args), ==, -1);
}
#elif QEMU_PLUGIN_VERSION >= 2
static void test_execution_mapping_requires_api_5(void)
{
	qemu_info_t info = {
		.target_name = "x86_64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[] = { "format=v1", "exec-mapping=on" };

	g_assert_cmpint(qemu_plugin_install(1, &info, 2, args), ==, -1);
}
#endif
#else
static void test_tb_execution_requires_api_2(void)
{
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 1, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	char *args[] = { "out=unused", "format=v1" };

	g_assert_cmpint(qemu_plugin_install(1, &info, 2, args), ==, -1);
}
#endif

static void test_execution_trace(void)
{
	struct qemu_plugin_insn insn = { .vaddr = 0x1000, .size = 4 };
	struct qemu_plugin_tb tb = {
		.vaddr = 0x1000,
		.insns = &insn,
		.n_insns = 1,
	};
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 1, .cur = QEMU_PLUGIN_VERSION },
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
#if QEMU_PLUGIN_VERSION >= 2
	g_assert_nonnull(tb.exec_cb);
#else
	g_assert_nonnull(insn.exec_cb);
#endif
	execute_tb_prefix(&tb, 3, tb.n_insns);
#if QEMU_PLUGIN_VERSION >= 2
	exit_vcpu(3);
#endif
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;

	read_data(&cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_INFO);
	g_assert_cmpuint(hdr.len, ==, sizeof(info_data));
	read_data(&cursor, &info_data, sizeof(info_data));
	g_assert_cmpuint(info_data.version.major, ==, 0);
	g_assert_cmpuint(info_data.attr, ==, ETRACE_INFO_F_FINAL_STATUS);

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
	g_assert_cmpuint(entry.end, ==, 0x1004);
	assert_status(&cursor, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}

#if QEMU_PLUGIN_VERSION >= 2
static void test_plugin_exit_flushes_vcpus(void)
{
	struct qemu_plugin_insn insn = { .vaddr = 0x1000, .size = 4 };
	struct qemu_plugin_tb tb = {
		.vaddr = 0x1000,
		.insns = &insn,
		.n_insns = 1,
	};
	qemu_info_t info = {
		.target_name = "aarch64",
		.version = { .min = 2, .cur = QEMU_PLUGIN_VERSION },
		.system_emulation = true,
	};
	struct etrace_status status;
	char *arg;
	char *contents;
	char *path = NULL;
	const uint8_t *cursor;
	gsize length;
	int fd;

	fd = g_file_open_tmp("qemu-etrace-plugin-XXXXXX", &path, NULL);
	g_assert_cmpint(fd, >=, 0);
	close(fd);
	unlink(path);
	arg = g_strdup_printf("out=%s", path);

	g_assert_cmpint(qemu_plugin_install(1, &info, 1, &arg), ==, 0);
	translate_tb(&tb);
	execute_tb_prefix(&tb, 1, tb.n_insns);
	execute_tb_prefix(&tb, 3, tb.n_insns);
	exit_vcpu(1);
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	g_assert_cmpuint(read_trace_headers(&cursor), ==,
			 ETRACE_INFO_F_FINAL_STATUS);
	assert_exec64(&cursor, 1, 0x1000, 0x1004);
	assert_exec64(&cursor, 3, 0x1000, 0x1004);
	status = read_status(&cursor);
	g_assert_cmpuint(status.unresolved_tb_exits, ==, 0);
	g_assert_cmpuint(status.unresolved_discontinuities, ==, 0);
	g_assert_cmpuint(status.unresolved_vcpu_exits, ==, 0);
	g_assert_cmpuint(status.output_errors, ==, 0);
	g_assert_cmpuint(status.discontinuity_pc_mismatches, ==, 0);
	g_assert_cmpuint(cursor - (const uint8_t *)contents, ==, length);

	unlink(path);
	g_free(contents);
	g_free(arg);
	g_free(path);
}
#endif

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
#if QEMU_PLUGIN_VERSION >= 2
	exit_vcpu(2);
#endif
	finish_plugin();

	g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
	cursor = (const uint8_t *)contents;
	read_data(&cursor, &hdr, sizeof(hdr));
	read_data(&cursor, &info_data, sizeof(info_data));
	g_assert_cmpuint(info_data.attr, ==, ETRACE_INFO_F_FINAL_STATUS);
	read_data(&cursor, &hdr, sizeof(hdr));
	read_data(&cursor, &arch, sizeof(arch));
	g_assert_cmpuint(arch.guest.arch_bits, ==, 32);
	read_data(&cursor, &hdr, sizeof(hdr));
	g_assert_cmpuint(hdr.type, ==, TYPE_EXEC);
	read_data(&cursor, &start_time, sizeof(start_time));
	read_data(&cursor, &entry, sizeof(entry));
	g_assert_cmpuint(entry.start, ==, 0x2000);
	g_assert_cmpuint(entry.end, ==, 0x2002);
	assert_status(&cursor, 0);
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
#if QEMU_PLUGIN_VERSION >= 2
	exit_vcpu(4);
#endif
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
	assert_status(&cursor, 0);
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
#if QEMU_PLUGIN_VERSION >= 3
	g_test_add_func("/plugin/scoreboard-inline-store-model",
			test_scoreboard_inline_store_model);
#endif
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
	g_test_add_func("/plugin/discontinuity-callback-model",
			test_discontinuity_callback_model);
	g_test_add_func("/plugin/discontinuity-trace",
			test_discontinuity_trace);
#endif
#if QEMU_PLUGIN_VERSION < 2
	g_test_add_func("/plugin/instruction-execution-trace",
			test_instruction_execution_trace);
#endif
	g_test_add_func("/plugin/gzip-equivalence", test_gzip_equivalence);
	g_test_add_func("/plugin/invalid-option", test_invalid_option);
#if QEMU_PLUGIN_VERSION >= 2
	g_test_add_func("/plugin/accurate-execution-trace",
			test_accurate_execution_trace);
	g_test_add_func("/plugin/exit-flushes-vcpus",
			test_plugin_exit_flushes_vcpus);
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
	g_test_add_func("/plugin/unreported-system-transition",
			test_unreported_system_transition);
	g_test_add_func("/plugin/accurate-internal-restart",
			test_accurate_internal_restart);
#endif
#endif

#if QEMU_PLUGIN_VERSION >= 2
	g_test_add_func("/plugin/tb-execution-trace",
			test_tb_execution_trace);
	g_test_add_func("/plugin/hypervisor-filter", test_hypervisor_filter);
	g_test_add_func("/plugin/context-filter-options",
			test_context_filter_options);
	g_test_add_func("/plugin/hypervisor-filter-partial-tb",
			test_hypervisor_filter_rejects_partial_tb);
	g_test_add_func("/plugin/register-context-changes",
			test_register_context_changes);
	g_test_add_func("/plugin/context-register-options",
			test_context_register_options);
	g_test_add_func("/plugin/missing-context-register",
			test_missing_context_register);
#if QEMU_PLUGIN_VERSION >= 5
	g_test_add_func("/plugin/execution-mappings", test_execution_mappings);
	g_test_add_func("/plugin/execution-mapping-failure",
			test_execution_mapping_failure);
	g_test_add_func("/plugin/execution-mapping-requires-v1",
			test_execution_mapping_requires_v1);
	g_test_add_func("/plugin/execution-mapping-requires-system",
			test_execution_mapping_requires_system_emulation);
#else
	g_test_add_func("/plugin/execution-mapping-requires-api-5",
			test_execution_mapping_requires_api_5);
#endif
#else
	g_test_add_func("/plugin/tb-execution-requires-api-2",
			test_tb_execution_requires_api_2);
#endif
	g_test_add_func("/plugin/execution-trace", test_execution_trace);
	g_test_add_func("/plugin/32bit-execution-trace",
			test_32bit_execution_trace);
	g_test_add_func("/plugin/gzip-execution-trace",
			test_gzip_execution_trace);

	return g_test_run();
}
