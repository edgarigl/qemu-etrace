#ifndef TEST_QEMU_PLUGIN_H
#define TEST_QEMU_PLUGIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define QEMU_PLUGIN_EXPORT __attribute__((visibility("default")))
#ifndef QEMU_PLUGIN_VERSION
#define QEMU_PLUGIN_VERSION 5
#endif

typedef uint64_t qemu_plugin_id_t;

typedef struct qemu_info_t {
	const char *target_name;
	struct {
		int min;
		int cur;
	} version;
	bool system_emulation;
	union {
		struct {
			int smp_vcpus;
			int max_vcpus;
		} system;
	};
} qemu_info_t;

struct qemu_plugin_tb;
struct qemu_plugin_insn;
#if QEMU_PLUGIN_VERSION >= 2
struct qemu_plugin_scoreboard;

typedef struct {
	struct qemu_plugin_scoreboard *score;
	size_t offset;
} qemu_plugin_u64;

#define qemu_plugin_scoreboard_u64_in_struct(score, type, member) \
	(qemu_plugin_u64) { score, offsetof(type, member) }
#endif

typedef void (*qemu_plugin_vcpu_udata_cb_t)(unsigned int cpu_index,
					    void *userdata);
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
enum qemu_plugin_discon_type {
	QEMU_PLUGIN_DISCON_INTERRUPT = 1 << 0,
	QEMU_PLUGIN_DISCON_EXCEPTION = 1 << 1,
	QEMU_PLUGIN_DISCON_HOSTCALL = 1 << 2,
	QEMU_PLUGIN_DISCON_ALL = -1,
};
#if QEMU_PLUGIN_VERSION >= 7
typedef void (*qemu_plugin_vcpu_discon_cb_t)(
	unsigned int cpu_index, enum qemu_plugin_discon_type type,
	uint64_t from_pc, uint64_t to_pc, void *userdata);
#else
typedef void (*qemu_plugin_vcpu_discon_cb_t)(
	qemu_plugin_id_t id, unsigned int cpu_index,
	enum qemu_plugin_discon_type type, uint64_t from_pc, uint64_t to_pc);
#endif
#endif
#if QEMU_PLUGIN_VERSION >= 7
typedef void (*qemu_plugin_udata_cb_t)(void *userdata);
typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(struct qemu_plugin_tb *tb,
					       void *userdata);
#else
typedef void (*qemu_plugin_udata_cb_t)(qemu_plugin_id_t id, void *userdata);
typedef void (*qemu_plugin_vcpu_simple_cb_t)(qemu_plugin_id_t id,
					      unsigned int cpu_index);
typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(qemu_plugin_id_t id,
					       struct qemu_plugin_tb *tb);
#endif

enum qemu_plugin_cb_flags {
	QEMU_PLUGIN_CB_NO_REGS,
};

#if QEMU_PLUGIN_VERSION >= 2
enum qemu_plugin_op {
	QEMU_PLUGIN_INLINE_ADD_U64,
	QEMU_PLUGIN_INLINE_STORE_U64,
};
#endif

#if QEMU_PLUGIN_VERSION >= 7
void qemu_plugin_register_vcpu_tb_trans_cb(
	qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb, void *userdata);
#else
void qemu_plugin_register_vcpu_tb_trans_cb(
	qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb);
#endif
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
#if QEMU_PLUGIN_VERSION >= 7
void qemu_plugin_register_vcpu_discon_cb(
	qemu_plugin_id_t id, enum qemu_plugin_discon_type type,
	qemu_plugin_vcpu_discon_cb_t cb, void *userdata);
#else
void qemu_plugin_register_vcpu_discon_cb(
	qemu_plugin_id_t id, enum qemu_plugin_discon_type type,
	qemu_plugin_vcpu_discon_cb_t cb);
#endif
#endif
#if QEMU_PLUGIN_VERSION >= 7
void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
				       qemu_plugin_vcpu_udata_cb_t cb,
				       void *userdata);
#else
void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
				       qemu_plugin_vcpu_simple_cb_t cb);
#endif
void qemu_plugin_register_vcpu_tb_exec_cb(
	struct qemu_plugin_tb *tb, qemu_plugin_vcpu_udata_cb_t cb,
	enum qemu_plugin_cb_flags flags, void *userdata);
void qemu_plugin_register_vcpu_insn_exec_cb(
	struct qemu_plugin_insn *insn, qemu_plugin_vcpu_udata_cb_t cb,
	enum qemu_plugin_cb_flags flags, void *userdata);
#if QEMU_PLUGIN_VERSION >= 2
void qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
	struct qemu_plugin_insn *insn, enum qemu_plugin_op op,
	qemu_plugin_u64 entry, uint64_t imm);
#endif
void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id,
				     qemu_plugin_udata_cb_t cb,
				     void *userdata);

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb);
uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb);
struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t index);
uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn);
size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn);
#if QEMU_PLUGIN_VERSION >= 5
bool qemu_plugin_translate_vaddr(uint64_t vaddr, uint64_t *hwaddr);
#endif

#if QEMU_PLUGIN_VERSION >= 2
struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size);
void qemu_plugin_scoreboard_free(struct qemu_plugin_scoreboard *score);
void *qemu_plugin_scoreboard_find(struct qemu_plugin_scoreboard *score,
				  unsigned int cpu_index);
uint64_t qemu_plugin_u64_get(qemu_plugin_u64 entry,
			     unsigned int cpu_index);
void qemu_plugin_u64_set(qemu_plugin_u64 entry, unsigned int cpu_index,
			 uint64_t value);
#endif

#endif
