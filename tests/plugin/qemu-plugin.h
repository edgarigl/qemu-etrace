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

typedef void (*qemu_plugin_vcpu_udata_cb_t)(unsigned int cpu_index,
					    void *userdata);
#if QEMU_PLUGIN_VERSION >= 7
typedef void (*qemu_plugin_udata_cb_t)(void *userdata);
typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(struct qemu_plugin_tb *tb,
					       void *userdata);
#else
typedef void (*qemu_plugin_udata_cb_t)(qemu_plugin_id_t id, void *userdata);
typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(qemu_plugin_id_t id,
					       struct qemu_plugin_tb *tb);
#endif

enum qemu_plugin_cb_flags {
	QEMU_PLUGIN_CB_NO_REGS,
};

#if QEMU_PLUGIN_VERSION >= 7
void qemu_plugin_register_vcpu_tb_trans_cb(
	qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb, void *userdata);
#else
void qemu_plugin_register_vcpu_tb_trans_cb(
	qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb);
#endif
void qemu_plugin_register_vcpu_tb_exec_cb(
	struct qemu_plugin_tb *tb, qemu_plugin_vcpu_udata_cb_t cb,
	enum qemu_plugin_cb_flags flags, void *userdata);
void qemu_plugin_register_vcpu_insn_exec_cb(
	struct qemu_plugin_insn *insn, qemu_plugin_vcpu_udata_cb_t cb,
	enum qemu_plugin_cb_flags flags, void *userdata);
void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id,
				     qemu_plugin_udata_cb_t cb,
				     void *userdata);

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb);
uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb);
struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t index);
uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn);
size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn);

#endif
