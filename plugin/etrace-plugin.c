/*
 * QEMU TCG plugin for ETrace execution records.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <zlib.h>

#include <qemu-plugin.h>

#include "etrace-format.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

struct tb_data {
	struct tb_data *next;
	uint64_t id;
	uint64_t start;
	uint64_t end;
	size_t n_insns;
	struct etrace_tb_mapping *mappings;
	size_t n_mappings;
	bool included;
	struct {
		uint64_t start;
		uint64_t end;
	} insns[];
};

#if QEMU_PLUGIN_VERSION >= 2
struct vcpu_exec_state {
	struct tb_data *pending;
	uint64_t pending_context_id;
	uint64_t progress;
	uint64_t sequence;
	uint64_t last_included_context_id;
	uint64_t gap_from_context_id;
	uint64_t filtered_execs;
	GArray *context_registers;
	GByteArray *context_sample;
	GByteArray *last_context_sample;
	uint64_t current_context_id;
	uint64_t address_space_id;
	uint64_t virtual_machine_id;
	uint32_t context_flags;
	uint8_t privilege;
	bool context_incomplete;
	bool gap_open;
	bool seen;
};

struct context_register {
	struct qemu_plugin_register *handle;
	char *name;
	GByteArray *value;
};
#endif

struct etrace_info_packet {
	struct etrace_hdr hdr;
	struct etrace_info_data data;
} __attribute__ ((packed));

struct etrace_arch_packet {
	struct etrace_hdr hdr;
	struct etrace_arch data;
} __attribute__ ((packed));

struct etrace_exec_packet {
	struct etrace_hdr hdr;
	uint64_t start_time;
	struct etrace_entry64 entry;
} __attribute__ ((packed));

struct etrace_exec_packet32 {
	struct etrace_hdr hdr;
	uint64_t start_time;
	struct etrace_entry32 entry;
} __attribute__ ((packed));

struct etrace_discontinuity_packet {
	struct etrace_hdr hdr;
	struct etrace_discontinuity data;
} __attribute__ ((packed));

struct etrace_status_packet {
	struct etrace_hdr hdr;
	struct etrace_status data;
} __attribute__ ((packed));

struct producer_status {
	uint64_t unresolved_tb_exits;
	uint64_t unresolved_discontinuities;
	uint64_t unresolved_vcpu_exits;
	uint64_t output_errors;
	uint64_t discontinuity_pc_mismatches;
	uint64_t filtered_execs;
	uint64_t context_errors;
	uint64_t mapping_errors;
};

struct context_range {
	uint64_t start;
	uint64_t end;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct tb_data *translated_blocks;
static int trace_fd = -1;
static gzFile trace_gz;
static bool trace_failed;
static uint8_t guest_address_bits;
static int gzip_level = Z_BEST_SPEED;
static bool gzip_output;
static bool tb_exec_output;
static bool hypervisor_filter;
static bool exec_mapping;
static bool context_enabled;
static bool context_register_all;
static bool context_register_basic;
static char **context_register_names;
static uint16_t target_architecture;
static uint64_t next_tb_id;
static uint64_t next_context_id;
static struct context_range *context_ranges;
static size_t nr_context_ranges;
static struct producer_status producer_status;
#if QEMU_PLUGIN_VERSION >= 2
static struct qemu_plugin_scoreboard *exec_state;
static qemu_plugin_u64 exec_progress;
static bool have_vcpu;
static unsigned int max_vcpu_index;
#endif

static bool write_raw(const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len) {
		ssize_t ret = write(trace_fd, p, len);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		if (ret == 0)
			return false;
		p += ret;
		len -= (size_t)ret;
	}
	return true;
}

static bool write_output(const void *buf, size_t len)
{
	const uint8_t *p = buf;

	if (!trace_gz)
		return write_raw(buf, len);

	while (len) {
		unsigned int chunk = len > UINT_MAX ? UINT_MAX : (unsigned int)len;
		int ret = gzwrite(trace_gz, p, chunk);

		if (ret <= 0)
			return false;
		p += ret;
		len -= (size_t)ret;
	}
	return true;
}

static const char *output_error(void)
{
	int error;

	if (trace_gz)
		return gzerror(trace_gz, &error);
	return strerror(errno);
}

static void write_packet(const void *packet, size_t len)
{
	pthread_mutex_lock(&lock);
	if (!trace_failed && !write_output(packet, len)) {
		fprintf(stderr, "qemu-etrace-plugin: write: %s\n", output_error());
		trace_failed = true;
		producer_status.output_errors++;
	}
	pthread_mutex_unlock(&lock);
}

static uint8_t target_bits(const char *target_name)
{
	if (!target_name)
		return 64;
	if (strstr(target_name, "64") || !strcmp(target_name, "alpha")
	    || !strcmp(target_name, "s390x"))
		return 64;
	return 32;
}

static bool write_headers(void)
{
	struct etrace_info_packet info_packet = {
		.hdr = {
			.type = TYPE_INFO,
			.len = sizeof(info_packet.data),
		},
		.data = {
			.attr = ETRACE_INFO_F_FINAL_STATUS
				| (tb_exec_output ? ETRACE_INFO_F_TB_EXEC : 0)
				| (context_enabled ? ETRACE_INFO_F_CONTEXT : 0)
				| (hypervisor_filter ? ETRACE_INFO_F_FILTERED : 0)
				| (exec_mapping ? ETRACE_INFO_F_EXEC_MAPPING : 0),
			.version = {
				.major = tb_exec_output ? ETRACE_VERSION_TB_EXEC
					: ETRACE_VERSION_LEGACY,
				.minor = 0,
			},
		},
	};
	struct etrace_arch_packet arch_packet = {
		.hdr = {
			.type = TYPE_ARCH,
			.len = sizeof(arch_packet.data),
		},
		.data = {
			.guest = {
				.arch_id = 0,
				.arch_bits = guest_address_bits,
				.big_endian = 0,
			},
			.host = {
				.arch_id = 0,
				.arch_bits = sizeof(void *) * 8,
				.big_endian = 0,
			},
		},
	};

	if (!write_output(&info_packet, sizeof(info_packet))
	    || !write_output(&arch_packet, sizeof(arch_packet)))
		return false;
	return true;
}

static bool add_context_range(const char *arg)
{
	struct context_range *ranges;
	unsigned long long start;
	unsigned long long size;
	char *separator;
	char *end;

	errno = 0;
	start = strtoull(arg, &separator, 0);
	if (errno || separator == arg || *separator != ':')
		return false;
	errno = 0;
	size = strtoull(separator + 1, &end, 0);
	if (errno || end == separator + 1 || *end || !size
	    || start > UINT64_MAX - size)
		return false;
	ranges = realloc(context_ranges,
			 (nr_context_ranges + 1) * sizeof(*context_ranges));
	if (!ranges)
		return false;
	context_ranges = ranges;
	context_ranges[nr_context_ranges].start = start;
	context_ranges[nr_context_ranges].end = start + size;
	nr_context_ranges++;
	return true;
}

#if QEMU_PLUGIN_VERSION >= 2
static int classify_context_range(uint64_t start, uint64_t end)
{
	bool overlaps = false;
	size_t i;

	for (i = 0; i < nr_context_ranges; i++) {
		if (start >= context_ranges[i].start
		    && end <= context_ranges[i].end)
			return 1;
		if (start < context_ranges[i].end
		    && end > context_ranges[i].start)
			overlaps = true;
	}
	return overlaps ? -1 : 0;
}
#endif

static void clear_context_register_names(void)
{
	g_strfreev(context_register_names);
	context_register_names = NULL;
	context_register_all = false;
	context_register_basic = false;
}

static bool set_context_register_names(const char *names)
{
	size_t i;
	size_t j;

	clear_context_register_names();
	if (!strcmp(names, "none"))
		return true;
	if (!strcmp(names, "all")) {
		context_register_all = true;
		return true;
	}
	if (!strcmp(names, "basic")) {
		context_register_basic = true;
		return true;
	}
	context_register_names = g_strsplit(names, ",", -1);
	for (i = 0; context_register_names[i]; i++) {
		if (!context_register_names[i][0] || i == UINT8_MAX)
			goto invalid;
		for (j = 0; j < i; j++) {
			if (!strcmp(context_register_names[i],
				    context_register_names[j]))
				goto invalid;
		}
	}
	return i != 0;

invalid:
	clear_context_register_names();
	return false;
}

static bool add_context_register_name(const char *name)
{
	char **names;
	size_t count = 0;
	size_t i;

	if (!name[0] || strchr(name, ',') || context_register_all
	    || context_register_basic)
		return false;
	if (context_register_names) {
		while (context_register_names[count])
			count++;
	}
	if (count == UINT8_MAX)
		return false;
	for (i = 0; i < count; i++) {
		if (!strcmp(context_register_names[i], name))
			return false;
	}
	names = g_realloc_n(context_register_names, count + 2, sizeof(*names));
	context_register_names = names;
	context_register_names[count] = g_strdup(name);
	context_register_names[count + 1] = NULL;
	return true;
}

static bool configure_basic_context(const char *target_name)
{
	const char *names;

	if (!target_name)
		return false;
	if (!strcmp(target_name, "x86_64") || !strcmp(target_name, "i386")) {
		names = "cs,eflags,cr0,cr3,cr4,efer";
	} else if (!strcmp(target_name, "aarch64")) {
		names = "cpsr,ttbr0_el1,ttbr1_el1,tcr_el1,sctlr_el1,hcr_el2,"
			"vttbr_el2,vtcr_el2,scr_el3";
	} else if (!strcmp(target_name, "riscv32")
		   || !strcmp(target_name, "riscv64")) {
		names = "priv,mstatus,sstatus,satp,hstatus,hgatp";
	} else {
		return false;
	}
	context_register_basic = false;
	return set_context_register_names(names);
}

static void configure_target_architecture(const char *target_name)
{
	if (!target_name) {
		target_architecture = EM_NONE;
		return;
	}
	if (!strcmp(target_name, "x86_64"))
		target_architecture = EM_X86_64;
	else if (!strcmp(target_name, "i386"))
		target_architecture = EM_386;
	else if (!strcmp(target_name, "aarch64"))
		target_architecture = EM_AARCH64;
	else if (!strcmp(target_name, "arm"))
		target_architecture = EM_ARM;
	else if (!strcmp(target_name, "riscv32")
		 || !strcmp(target_name, "riscv64"))
		target_architecture = EM_RISCV;
	else
		target_architecture = EM_NONE;
}

#if QEMU_PLUGIN_VERSION >= 5
static bool append_mapping(struct tb_data *tb, uint64_t vaddr,
			   uint64_t paddr, uint64_t len)
{
	struct etrace_tb_mapping *mapping;
	struct etrace_tb_mapping *mappings;

	if (vaddr < tb->start || vaddr - tb->start > UINT32_MAX
	    || !len || len > UINT32_MAX
	    || paddr > UINT64_MAX - len)
		return false;
	if (tb->n_mappings) {
		mapping = &tb->mappings[tb->n_mappings - 1];
		if ((uint64_t)mapping->offset + mapping->len == vaddr - tb->start
		    && mapping->paddr + mapping->len == paddr
		    && (uint64_t)mapping->len + len <= UINT32_MAX) {
			mapping->len += len;
			return true;
		}
	}
	if (tb->n_mappings == UINT16_MAX)
		return false;
	mappings = realloc(tb->mappings,
			   (tb->n_mappings + 1) * sizeof(*tb->mappings));
	if (!mappings)
		return false;
	tb->mappings = mappings;
	mapping = &tb->mappings[tb->n_mappings++];
	mapping->offset = vaddr - tb->start;
	mapping->len = len;
	mapping->paddr = paddr;
	return true;
}

static bool collect_mappings(struct tb_data *tb)
{
	size_t i;

	for (i = 0; i < tb->n_insns; i++) {
		uint64_t start = tb->insns[i].start;
		uint64_t size = tb->insns[i].end - start;
		uint64_t pstart;
		uint64_t pend;

		if (!qemu_plugin_translate_vaddr(start, &pstart)
		    || !qemu_plugin_translate_vaddr(tb->insns[i].end - 1,
						   &pend))
			goto fail;
		if (pstart <= UINT64_MAX - (size - 1)
		    && pstart + size - 1 == pend) {
			if (!append_mapping(tb, start, pstart, size))
				goto fail;
		} else {
			uint64_t offset;

			for (offset = 0; offset < size; offset++) {
				uint64_t paddr;

				if (!qemu_plugin_translate_vaddr(start + offset,
							 &paddr)
				    || !append_mapping(tb, start + offset, paddr, 1))
					goto fail;
			}
		}
	}
	return true;

fail:
	free(tb->mappings);
	tb->mappings = NULL;
	tb->n_mappings = 0;
	return false;
}
#endif

#if QEMU_PLUGIN_VERSION >= 2
static void write_tb_definition(const struct tb_data *tb)
{
	struct etrace_tb_def *definition;
	struct etrace_tb_insn *insns;
	struct etrace_hdr *hdr;
	uint8_t *packet;
	size_t payload_len;
	size_t packet_len;
	size_t i;

	payload_len = offsetof(struct etrace_tb_def, data8)
		+ tb->n_insns * sizeof(*insns)
		+ tb->n_mappings * sizeof(*tb->mappings);
	packet_len = sizeof(*hdr) + payload_len;
	packet = calloc(1, packet_len);
	if (!packet) {
		fprintf(stderr,
			"qemu-etrace-plugin: unable to allocate TB definition\n");
		trace_failed = true;
		producer_status.output_errors++;
		return;
	}

	hdr = (void *)packet;
	definition = (void *)(packet + sizeof(*hdr));
	insns = (void *)definition->data8;
	hdr->type = TYPE_TB_DEF;
	hdr->len = payload_len;
	definition->tb_id = tb->id;
	definition->vaddr = tb->start;
	definition->context_id = 0;
	definition->size = tb->end - tb->start;
	definition->insn_count = tb->n_insns;
	definition->mapping_count = tb->n_mappings;
	for (i = 0; i < tb->n_insns; i++) {
		insns[i].offset = tb->insns[i].start - tb->start;
		insns[i].size = tb->insns[i].end - tb->insns[i].start;
	}
	if (tb->n_mappings) {
		memcpy(&insns[tb->n_insns], tb->mappings,
		       tb->n_mappings * sizeof(*tb->mappings));
	}
	write_packet(packet, packet_len);
	free(packet);
}
#endif

static void write_exec_range(unsigned int cpu_index, uint64_t start,
			     uint64_t end)
{
	uint16_t unit_id = (uint16_t)cpu_index;
	struct etrace_exec_packet32 packet32 = {
		.hdr = {
			.type = TYPE_EXEC,
			.unit_id = unit_id,
			.len = sizeof(packet32) - sizeof(packet32.hdr),
		},
		.start_time = 0,
		.entry = {
			.duration = 0,
			.start = (uint32_t)start,
			.end = (uint32_t)end,
		},
	};
	struct etrace_exec_packet packet = {
		.hdr = {
			.type = TYPE_EXEC,
			.unit_id = unit_id,
			.len = sizeof(packet) - sizeof(packet.hdr),
		},
		.start_time = 0,
		.entry = {
			.duration = 0,
			.start = start,
			.end = end,
		},
	};

	if (guest_address_bits == 32)
		write_packet(&packet32, sizeof(packet32));
	else
		write_packet(&packet, sizeof(packet));
}

#if QEMU_PLUGIN_VERSION >= 2
static void write_tb_execution(unsigned int cpu_index,
			       const struct tb_data *tb,
			       uint64_t sequence, uint64_t context_id,
			       uint64_t progress)
{
	struct {
		struct etrace_hdr hdr;
		struct etrace_tb_exec data;
	} __attribute__ ((packed)) packet = {
		.hdr = {
			.type = TYPE_TB_EXEC,
			.unit_id = (uint16_t)cpu_index,
			.len = sizeof(packet.data),
		},
		.data = {
			.sequence = sequence,
			.tb_id = tb->id,
			.context_id = context_id,
			.insn_count = (uint16_t)progress,
		},
	};

	write_packet(&packet, sizeof(packet));
}

static void write_context_gap(unsigned int cpu_index,
			      struct vcpu_exec_state *state,
			      uint64_t to_context_id)
{
	struct {
		struct etrace_hdr hdr;
		struct etrace_context_gap data;
	} __attribute__ ((packed)) packet = {
		.hdr = {
			.type = TYPE_CONTEXT_GAP,
			.unit_id = (uint16_t)cpu_index,
			.len = sizeof(packet.data),
		},
		.data = {
			.sequence = ++state->sequence,
			.from_context_id = state->gap_from_context_id,
			.to_context_id = to_context_id,
			.filtered_execs = state->filtered_execs,
			.reason = ETRACE_CONTEXT_GAP_FILTERED,
		},
	};

	write_packet(&packet, sizeof(packet));
	state->gap_open = false;
	state->gap_from_context_id = 0;
	state->filtered_execs = 0;
}
#endif

#if QEMU_PLUGIN_VERSION < 2
static void vcpu_exec(unsigned int cpu_index, void *userdata)
{
	const struct tb_data *tb = userdata;

	write_exec_range(cpu_index, tb->start, tb->end);
}
#endif

#if QEMU_PLUGIN_VERSION >= 2
static void increment_status_counter(uint64_t *counter)
{
	pthread_mutex_lock(&lock);
	(*counter)++;
	pthread_mutex_unlock(&lock);
}

static void record_vcpu(struct vcpu_exec_state *state,
			unsigned int cpu_index)
{
	if (state->seen)
		return;
	state->seen = true;

	pthread_mutex_lock(&lock);
	if (!have_vcpu || cpu_index > max_vcpu_index)
		max_vcpu_index = cpu_index;
	have_vcpu = true;
	pthread_mutex_unlock(&lock);
}

static bool context_register_requested(const char *name)
{
	size_t i;

	if (context_register_all)
		return true;
	if (!context_register_names)
		return false;
	for (i = 0; context_register_names[i]; i++) {
		if (!strcmp(name, context_register_names[i]))
			return true;
	}
	return false;
}

static void report_context_error(struct vcpu_exec_state *state)
{
	if (state->context_incomplete)
		return;
	state->context_incomplete = true;
	increment_status_counter(&producer_status.context_errors);
}

static void initialize_context_registers(unsigned int cpu_index)
{
	struct vcpu_exec_state *state;
	GArray *available;
	size_t selected = 0;
	size_t requested = 0;
	unsigned int i;

	state = qemu_plugin_scoreboard_find(exec_state, cpu_index);
	record_vcpu(state, cpu_index);
	state->context_registers = g_array_new(false, true,
					       sizeof(struct context_register));
	state->context_sample = g_byte_array_new();
	state->last_context_sample = g_byte_array_new();
	available = qemu_plugin_get_registers();
	if (context_register_names) {
		while (context_register_names[requested])
			requested++;
	}

	for (i = 0; i < available->len; i++) {
		qemu_plugin_reg_descriptor *descriptor =
			&g_array_index(available, qemu_plugin_reg_descriptor, i);
		struct context_register reg;

		if (!context_register_requested(descriptor->name))
			continue;
		if (selected == UINT8_MAX
		    || strlen(descriptor->name) > UINT16_MAX) {
			report_context_error(state);
			break;
		}
		reg.handle = descriptor->handle;
		reg.name = g_strdup(descriptor->name);
		reg.value = g_byte_array_new();
		g_array_append_val(state->context_registers, reg);
		selected++;
	}
	if ((!context_register_all && selected != requested)
	    || (context_register_all && !selected))
		report_context_error(state);
	g_array_free(available, true);
}

#if QEMU_PLUGIN_VERSION >= 7
static void vcpu_init(unsigned int cpu_index, void *userdata)
#else
static void vcpu_init(qemu_plugin_id_t id, unsigned int cpu_index)
#endif
{
#if QEMU_PLUGIN_VERSION >= 7
	(void) userdata;
#else
	(void) id;
#endif
	initialize_context_registers(cpu_index);
}

static uint64_t read_register_u64(const GByteArray *value)
{
	uint64_t result = 0;
	size_t len = value->len < sizeof(result) ? value->len : sizeof(result);
	size_t i;

	for (i = 0; i < len; i++)
		result |= (uint64_t)value->data[i] << (i * 8);
	return result;
}

static uint64_t hash_context(uint32_t flags, uint64_t address_space_id,
			     uint64_t virtual_machine_id, uint8_t privilege,
			     const GByteArray *sample)
{
	const uint64_t prime = UINT64_C(1099511628211);
	uint64_t hash = UINT64_C(14695981039346656037);
	const uint8_t *fields[] = {
		(const uint8_t *)&flags,
		(const uint8_t *)&address_space_id,
		(const uint8_t *)&virtual_machine_id,
		&privilege,
		sample->data,
	};
	const size_t sizes[] = {
		sizeof(flags), sizeof(address_space_id),
		sizeof(virtual_machine_id), sizeof(privilege), sample->len,
	};
	size_t i;
	size_t j;

	for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		for (j = 0; j < sizes[i]; j++) {
			hash ^= fields[i][j];
			hash *= prime;
		}
	}
	return hash;
}

static void write_context(unsigned int cpu_index, uint64_t pc,
			  uint64_t context_id, uint64_t address_space_id,
			  uint64_t virtual_machine_id, uint64_t state_hash,
			  uint32_t flags, uint8_t privilege,
			  uint8_t register_count, const GByteArray *sample)
{
	struct etrace_context *context;
	struct etrace_hdr *hdr;
	uint8_t *packet;
	size_t payload_len = offsetof(struct etrace_context, data8) + sample->len;
	size_t packet_len = sizeof(*hdr) + payload_len;

	packet = calloc(1, packet_len);
	if (!packet) {
		increment_status_counter(&producer_status.output_errors);
		return;
	}
	hdr = (void *)packet;
	context = (void *)(packet + sizeof(*hdr));
	hdr->type = TYPE_CONTEXT;
	hdr->unit_id = (uint16_t)cpu_index;
	hdr->len = payload_len;
	context->context_id = context_id;
	context->pc = pc;
	context->address_space_id = address_space_id;
	context->virtual_machine_id = virtual_machine_id;
	context->state_hash = state_hash;
	context->flags = flags;
	context->architecture = target_architecture;
	context->privilege = privilege;
	context->register_count = register_count;
	if (sample->len)
		memcpy(context->data8, sample->data, sample->len);
	write_packet(packet, packet_len);
	free(packet);
}

static uint64_t sample_context(struct vcpu_exec_state *state,
			       unsigned int cpu_index,
			       const struct tb_data *tb)
{
	uint64_t address_space_id = 0;
	uint64_t virtual_machine_id = 0;
	uint64_t state_hash;
	uint32_t flags = 0;
	uint8_t privilege = UINT8_MAX;
	uint8_t register_count = 0;
	unsigned int i;

	if (!context_enabled)
		return 0;
	if (hypervisor_filter && tb->included)
		flags |= ETRACE_CONTEXT_F_HYPERVISOR;
	if (!state->context_sample) {
		state->context_sample = g_byte_array_new();
		state->last_context_sample = g_byte_array_new();
	}
	g_byte_array_set_size(state->context_sample, 0);
	if ((context_register_all || context_register_names)
	    && !state->context_registers)
		report_context_error(state);
	if (state->context_incomplete)
		flags |= ETRACE_CONTEXT_F_INCOMPLETE;

	if (state->context_registers) {
		for (i = 0; i < state->context_registers->len; i++) {
			struct context_register *reg = &g_array_index(
				state->context_registers, struct context_register, i);
			struct etrace_context_register wire = {
				.name_len = strlen(reg->name),
			};
			uint64_t value;

			g_byte_array_set_size(reg->value, 0);
			if (qemu_plugin_read_register(reg->handle, reg->value) <= 0
			    || reg->value->len > UINT16_MAX) {
				report_context_error(state);
				flags |= ETRACE_CONTEXT_F_INCOMPLETE;
				continue;
			}
			wire.size = reg->value->len;
			g_byte_array_append(state->context_sample,
					    (const uint8_t *)&wire, sizeof(wire));
			g_byte_array_append(state->context_sample,
					    (const uint8_t *)reg->name,
					    wire.name_len);
			g_byte_array_append(state->context_sample,
					    reg->value->data, reg->value->len);
			register_count++;
			value = read_register_u64(reg->value);
			if (!strcmp(reg->name, "cs")) {
				privilege = value & 3;
				flags |= ETRACE_CONTEXT_F_PRIVILEGE_VALID;
			} else if (!strcmp(reg->name, "cr3")
				   || !strcmp(reg->name, "ttbr0_el1")
				   || !strcmp(reg->name, "satp")) {
				address_space_id = value;
				flags |= ETRACE_CONTEXT_F_ADDRESS_SPACE_VALID;
			} else if (!strcmp(reg->name, "priv")) {
				privilege = value;
				flags |= ETRACE_CONTEXT_F_PRIVILEGE_VALID;
			} else if (!strcmp(reg->name, "cpsr")) {
				privilege = (value >> 2) & 3;
				flags |= ETRACE_CONTEXT_F_PRIVILEGE_VALID;
			} else if (!strcmp(reg->name, "vttbr_el2")
				   || !strcmp(reg->name, "hgatp")) {
				virtual_machine_id = value;
				flags |= ETRACE_CONTEXT_F_VM_VALID;
			} else if (!strcmp(reg->name, "cr0")
				   && value & (UINT64_C(1) << 31)) {
				flags |= ETRACE_CONTEXT_F_PAGING;
			} else if (!strcmp(reg->name, "efer")
				   && value & (UINT64_C(1) << 10)) {
				flags |= ETRACE_CONTEXT_F_LONG_MODE;
			}
		}
	}
	state_hash = hash_context(flags, address_space_id, virtual_machine_id,
				  privilege, state->context_sample);
	if (state->current_context_id
	    && state->address_space_id == address_space_id
	    && state->virtual_machine_id == virtual_machine_id
	    && state->context_flags == flags
	    && state->privilege == privilege
	    && state->last_context_sample->len == state->context_sample->len
	    && (!state->context_sample->len
		|| !memcmp(state->last_context_sample->data,
			   state->context_sample->data,
			   state->context_sample->len)))
		return state->current_context_id;

	state->current_context_id = __atomic_add_fetch(&next_context_id, 1,
						       __ATOMIC_RELAXED);
	state->address_space_id = address_space_id;
	state->virtual_machine_id = virtual_machine_id;
	state->context_flags = flags;
	state->privilege = privilege;
	g_byte_array_set_size(state->last_context_sample,
			      state->context_sample->len);
	if (state->context_sample->len) {
		memcpy(state->last_context_sample->data, state->context_sample->data,
		       state->context_sample->len);
	}
	write_context(cpu_index, tb->start, state->current_context_id,
		      address_space_id, virtual_machine_id, state_hash, flags,
		      privilege, register_count, state->context_sample);
	return state->current_context_id;
}

static bool write_exec_prefix(unsigned int cpu_index,
			      const struct tb_data *tb, uint64_t end)
{
	if (tb_exec_output) {
		struct vcpu_exec_state *state;

		state = qemu_plugin_scoreboard_find(exec_state, cpu_index);
		if (!tb->included) {
			if (!state->gap_open) {
				state->gap_open = true;
				state->gap_from_context_id =
					state->last_included_context_id;
			}
			state->filtered_execs++;
			increment_status_counter(&producer_status.filtered_execs);
			return true;
		}
		if (!end)
			return true;
		if (end > tb->n_insns)
			return false;
		write_tb_execution(cpu_index, tb, ++state->sequence,
				   state->pending_context_id, end);
		state->last_included_context_id = state->pending_context_id;
		return true;
	}
#if QEMU_PLUGIN_VERSION == 2
	if (end > tb->n_insns)
		return false;
	if (end)
		end = tb->insns[end - 1].end;
#endif
	if (end > tb->start && end <= tb->end) {
		write_exec_range(cpu_index, tb->start, end);
		return true;
	}
	return end == 0 || end == tb->start;
}

static void vcpu_tb_exec(unsigned int cpu_index, void *userdata)
{
	struct vcpu_exec_state *state;
	struct tb_data *current = userdata;
	uint64_t current_context_id;
	uint64_t progress;

	state = qemu_plugin_scoreboard_find(exec_state, cpu_index);
	record_vcpu(state, cpu_index);
	current_context_id = sample_context(state, cpu_index, current);
	progress = qemu_plugin_u64_get(exec_progress, cpu_index);
	if (state->pending
	    && !write_exec_prefix(cpu_index, state->pending, progress))
		increment_status_counter(&producer_status.unresolved_tb_exits);
	if (current->included && state->gap_open)
		write_context_gap(cpu_index, state, current_context_id);
	state->pending = current;
	state->pending_context_id = current_context_id;
	qemu_plugin_u64_set(exec_progress, cpu_index, 0);
}

#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
static bool tb_has_boundary(const struct tb_data *tb, uint64_t pc)
{
	size_t i;

	if (pc == tb->end)
		return true;
	for (i = 0; i < tb->n_insns; i++) {
		if (tb->insns[i].start == pc)
			return true;
	}
	return false;
}

static void flush_discontinuity_range(unsigned int cpu_index,
				      enum qemu_plugin_discon_type type,
				      uint64_t from_pc)
{
	struct vcpu_exec_state *state;
	uint64_t progress;

	state = qemu_plugin_scoreboard_find(exec_state, cpu_index);
	if (!state->pending)
		return;

	if (type != QEMU_PLUGIN_DISCON_INTERRUPT
	    && !tb_has_boundary(state->pending, from_pc)) {
		increment_status_counter(
			&producer_status.discontinuity_pc_mismatches);
	}
	progress = qemu_plugin_u64_get(exec_progress, cpu_index);
	if (!write_exec_prefix(cpu_index, state->pending, progress))
		increment_status_counter(
			&producer_status.unresolved_discontinuities);

	state->pending = NULL;
	qemu_plugin_u64_set(exec_progress, cpu_index, 0);
	if (state->gap_open)
		write_context_gap(cpu_index, state, 0);
}
#endif

static void flush_vcpu(unsigned int cpu_index)
{
	struct vcpu_exec_state *state;
	uint64_t progress;

	state = qemu_plugin_scoreboard_find(exec_state, cpu_index);
	if (!state->pending)
		return;

	progress = qemu_plugin_u64_get(exec_progress, cpu_index);
	if (!write_exec_prefix(cpu_index, state->pending, progress))
		increment_status_counter(&producer_status.unresolved_vcpu_exits);

	state->pending = NULL;
	qemu_plugin_u64_set(exec_progress, cpu_index, 0);
	if (state->gap_open)
		write_context_gap(cpu_index, state, 0);
}

#if QEMU_PLUGIN_VERSION >= 7
static void vcpu_exit(unsigned int cpu_index, void *userdata)
#else
static void vcpu_exit(qemu_plugin_id_t id, unsigned int cpu_index)
#endif
{
#if QEMU_PLUGIN_VERSION >= 7
	(void) userdata;
#else
	(void) id;
#endif

	flush_vcpu(cpu_index);
}
#endif

#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
#if QEMU_PLUGIN_VERSION >= 7
static void vcpu_discontinuity(unsigned int cpu_index,
			       enum qemu_plugin_discon_type type,
			       uint64_t from_pc, uint64_t to_pc,
			       void *userdata)
#else
static void vcpu_discontinuity(qemu_plugin_id_t id, unsigned int cpu_index,
			       enum qemu_plugin_discon_type type,
			       uint64_t from_pc, uint64_t to_pc)
#endif
{
#if QEMU_PLUGIN_VERSION >= 2
	flush_discontinuity_range(cpu_index, type, from_pc);
#endif
	struct etrace_discontinuity_packet packet = {
		.hdr = {
			.type = TYPE_DISCONTINUITY,
			.unit_id = (uint16_t)cpu_index,
			.len = sizeof(packet.data),
		},
		.data = {
			.from_pc = from_pc,
			.to_pc = to_pc,
		},
	};

#if QEMU_PLUGIN_VERSION >= 7
	(void) userdata;
#else
	(void) id;
#endif

	switch (type) {
	case QEMU_PLUGIN_DISCON_INTERRUPT:
		packet.data.kind = ETRACE_DISCONTINUITY_INTERRUPT;
		break;
	case QEMU_PLUGIN_DISCON_EXCEPTION:
		packet.data.kind = ETRACE_DISCONTINUITY_EXCEPTION;
		break;
	case QEMU_PLUGIN_DISCON_HOSTCALL:
		packet.data.kind = ETRACE_DISCONTINUITY_HOST_CALL;
		break;
	default:
		packet.data.kind = ETRACE_DISCONTINUITY_UNKNOWN;
		break;
	}

	write_packet(&packet, sizeof(packet));
}
#endif

static struct tb_data *new_exec_data(uint64_t start, uint64_t last_addr,
				     size_t last_size, size_t n_insns)
{
	struct tb_data *data;
	size_t alloc_size;

	if (n_insns > (SIZE_MAX - sizeof(*data)) / sizeof(data->insns[0])) {
		fprintf(stderr, "qemu-etrace-plugin: execution data is too large\n");
		return NULL;
	}
	alloc_size = sizeof(*data) + n_insns * sizeof(data->insns[0]);
	data = calloc(1, alloc_size);
	if (!data) {
		fprintf(stderr, "qemu-etrace-plugin: unable to allocate execution data\n");
		return NULL;
	}
	data->id = __atomic_add_fetch(&next_tb_id, 1, __ATOMIC_RELAXED);
	data->start = start;
	if (last_size > UINT64_MAX - last_addr)
		data->end = UINT64_MAX;
	else
		data->end = last_addr + last_size;
	data->n_insns = n_insns;
	data->included = true;
#if QEMU_PLUGIN_VERSION >= 2
	if (hypervisor_filter) {
		int classification = classify_context_range(data->start, data->end);

		data->included = classification > 0;
		if (classification < 0)
			increment_status_counter(&producer_status.context_errors);
	}
#endif

	pthread_mutex_lock(&lock);
	data->next = translated_blocks;
	translated_blocks = data;
	pthread_mutex_unlock(&lock);

	return data;
}

#if QEMU_PLUGIN_VERSION >= 7
static void vcpu_tb_trans(struct qemu_plugin_tb *tb, void *userdata)
#else
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
#endif
{
#if QEMU_PLUGIN_VERSION >= 2
	struct qemu_plugin_insn *last_insn;
#endif
	struct tb_data *data;
	size_t n_insns;
	size_t i;

#if QEMU_PLUGIN_VERSION >= 7
	(void) userdata;
#else
	(void) id;
#endif

	n_insns = qemu_plugin_tb_n_insns(tb);
	if (n_insns == 0)
		return;

#if QEMU_PLUGIN_VERSION < 2
	{
		/* API version 1 has no inline per-vCPU scoreboard operations. */
		for (i = 0; i < n_insns; i++) {
			struct qemu_plugin_insn *insn;

			insn = qemu_plugin_tb_get_insn(tb, i);
			data = new_exec_data(qemu_plugin_insn_vaddr(insn),
					     qemu_plugin_insn_vaddr(insn),
					     qemu_plugin_insn_size(insn), 0);
			if (!data)
				continue;
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, vcpu_exec, QEMU_PLUGIN_CB_NO_REGS, data);
		}
		return;
	}
#else

	last_insn = qemu_plugin_tb_get_insn(tb, n_insns - 1);
	data = new_exec_data(qemu_plugin_tb_vaddr(tb),
			     qemu_plugin_insn_vaddr(last_insn),
			     qemu_plugin_insn_size(last_insn),
			     n_insns);
	if (!data)
		return;

	for (i = 0; i < n_insns; i++) {
		struct qemu_plugin_insn *insn;

		insn = qemu_plugin_tb_get_insn(tb, i);
		data->insns[i].start = qemu_plugin_insn_vaddr(insn);
		if (qemu_plugin_insn_size(insn)
		    > UINT64_MAX - data->insns[i].start)
			data->insns[i].end = UINT64_MAX;
		else
			data->insns[i].end = data->insns[i].start
				+ qemu_plugin_insn_size(insn);
		if (!hypervisor_filter || data->included) {
#if QEMU_PLUGIN_VERSION == 2
			qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
				insn, QEMU_PLUGIN_INLINE_ADD_U64,
				exec_progress, 1);
#else
			qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
				insn, QEMU_PLUGIN_INLINE_STORE_U64,
				exec_progress,
				tb_exec_output ? i + 1 : data->insns[i].end);
#endif
		}
	}
#if QEMU_PLUGIN_VERSION >= 5
	if (exec_mapping && (!hypervisor_filter || data->included)
	    && !collect_mappings(data))
		increment_status_counter(&producer_status.mapping_errors);
#endif
	if (tb_exec_output && (!hypervisor_filter || data->included))
		write_tb_definition(data);
	qemu_plugin_register_vcpu_tb_exec_cb(
		tb, vcpu_tb_exec,
		context_register_all || context_register_names
			? QEMU_PLUGIN_CB_R_REGS : QEMU_PLUGIN_CB_NO_REGS,
		data);
#endif
}

#if QEMU_PLUGIN_VERSION >= 7
static void plugin_exit(void *userdata)
#else
static void plugin_exit(qemu_plugin_id_t id, void *userdata)
#endif
{
	struct etrace_status_packet status_packet = {
		.hdr = {
			.type = TYPE_STATUS,
			.len = sizeof(status_packet.data),
		},
	};
	struct {
		struct etrace_hdr hdr;
		struct etrace_status_v1 data;
	} __attribute__ ((packed)) status_packet_v1 = {
		.hdr = {
			.type = TYPE_STATUS,
			.len = sizeof(status_packet_v1.data),
		},
	};
	struct tb_data *tb;
#if QEMU_PLUGIN_VERSION >= 2
	unsigned int cpu_index;
#endif

#if QEMU_PLUGIN_VERSION < 7
	(void) id;
#endif
	(void) userdata;

#if QEMU_PLUGIN_VERSION >= 2
	if (have_vcpu) {
		for (cpu_index = 0; cpu_index <= max_vcpu_index; cpu_index++) {
			struct vcpu_exec_state *state;

			state = qemu_plugin_scoreboard_find(exec_state, cpu_index);
			if (state->seen)
				flush_vcpu(cpu_index);
		}
	}
#endif

	pthread_mutex_lock(&lock);
	status_packet.data.unresolved_tb_exits =
		producer_status.unresolved_tb_exits;
	status_packet.data.unresolved_discontinuities =
		producer_status.unresolved_discontinuities;
	status_packet.data.unresolved_vcpu_exits =
		producer_status.unresolved_vcpu_exits;
	status_packet.data.output_errors = producer_status.output_errors;
	status_packet.data.discontinuity_pc_mismatches =
		producer_status.discontinuity_pc_mismatches;
	status_packet.data.flags = ETRACE_STATUS_F_COMPLETE;
	pthread_mutex_unlock(&lock);

	if (tb_exec_output) {
		status_packet_v1.data.base = status_packet.data;
		status_packet_v1.data.filtered_execs =
			producer_status.filtered_execs;
		status_packet_v1.data.context_errors =
			producer_status.context_errors;
		status_packet_v1.data.mapping_errors =
			producer_status.mapping_errors;
		write_packet(&status_packet_v1, sizeof(status_packet_v1));
	} else {
		write_packet(&status_packet, sizeof(status_packet));
	}

	pthread_mutex_lock(&lock);
	if (trace_gz) {
		if (gzclose(trace_gz) != Z_OK)
			fprintf(stderr, "qemu-etrace-plugin: unable to finish gzip output\n");
		trace_gz = NULL;
	} else if (trace_fd >= 0) {
		close(trace_fd);
		trace_fd = -1;
	}
	tb = translated_blocks;
	translated_blocks = NULL;
	pthread_mutex_unlock(&lock);

	while (tb) {
		struct tb_data *next = tb->next;

		free(tb->mappings);
		free(tb);
		tb = next;
	}
	free(context_ranges);
	context_ranges = NULL;
	nr_context_ranges = 0;

#if QEMU_PLUGIN_VERSION >= 2
	if (exec_state) {
		if (have_vcpu) {
			for (cpu_index = 0; cpu_index <= max_vcpu_index;
			     cpu_index++) {
				struct vcpu_exec_state *state =
					qemu_plugin_scoreboard_find(exec_state,
								    cpu_index);
				unsigned int i;

				if (!state->seen)
					continue;
				if (state->context_registers) {
					for (i = 0;
					     i < state->context_registers->len; i++) {
						struct context_register *reg =
							&g_array_index(
								state->context_registers,
								struct context_register, i);

						g_free(reg->name);
						g_byte_array_unref(reg->value);
					}
					g_array_free(state->context_registers, true);
				}
				if (state->context_sample)
					g_byte_array_unref(state->context_sample);
				if (state->last_context_sample)
					g_byte_array_unref(state->last_context_sample);
			}
		}
		qemu_plugin_scoreboard_free(exec_state);
		exec_state = NULL;
	}
#endif
	clear_context_register_names();
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
			int argc, char **argv)
{
	const char *output = "etrace.bin";
	char mode[] = "wb1";
	char *end;
	long level;
	int fd;
	int i;

	gzip_output = false;
	tb_exec_output = false;
	hypervisor_filter = false;
	exec_mapping = false;
	context_enabled = false;
	clear_context_register_names();
	configure_target_architecture(info->target_name);
	gzip_level = Z_BEST_SPEED;
	trace_failed = false;
	next_tb_id = 0;
	next_context_id = 0;
	free(context_ranges);
	context_ranges = NULL;
	nr_context_ranges = 0;
	memset(&producer_status, 0, sizeof(producer_status));
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "out=", 4) && argv[i][4]) {
			output = argv[i] + 4;
		} else if (!strcmp(argv[i], "compress=gzip")) {
			gzip_output = true;
		} else if (!strcmp(argv[i], "compress=none")) {
			gzip_output = false;
		} else if (!strncmp(argv[i], "level=", 6)) {
			errno = 0;
			level = strtol(argv[i] + 6, &end, 10);
			if (errno || *end || level < 0 || level > 9) {
				fprintf(stderr,
					"qemu-etrace-plugin: invalid gzip level: %s\n",
					argv[i] + 6);
				return -1;
			}
			gzip_level = (int)level;
		} else if (!strcmp(argv[i], "format=v0")) {
			tb_exec_output = false;
		} else if (!strcmp(argv[i], "format=v1")) {
#if QEMU_PLUGIN_VERSION >= 2
			tb_exec_output = true;
#else
			fprintf(stderr,
				"qemu-etrace-plugin: format v1 requires QEMU "
				"plugin API 2 or newer\n");
			return -1;
#endif
		} else if (!strcmp(argv[i], "context=hypervisor")) {
			hypervisor_filter = true;
		} else if (!strncmp(argv[i], "context-range=", 14)) {
			if (!add_context_range(argv[i] + 14)) {
				fprintf(stderr,
					"qemu-etrace-plugin: invalid context range: %s\n",
					argv[i] + 14);
				return -1;
			}
		} else if (!strcmp(argv[i], "exec-mapping=on")) {
#if QEMU_PLUGIN_VERSION >= 5
			exec_mapping = true;
#else
			fprintf(stderr,
				"qemu-etrace-plugin: execution mappings require QEMU "
				"plugin API 5 or newer\n");
			return -1;
#endif
		} else if (!strcmp(argv[i], "exec-mapping=off")) {
			exec_mapping = false;
		} else if (!strncmp(argv[i], "context-registers=", 18)) {
			if (!set_context_register_names(argv[i] + 18)) {
				fprintf(stderr,
					"qemu-etrace-plugin: invalid context register list: %s\n",
					argv[i] + 18);
				return -1;
			}
		} else if (!strncmp(argv[i], "context-register=", 17)) {
			if (!add_context_register_name(argv[i] + 17)) {
				fprintf(stderr,
					"qemu-etrace-plugin: invalid context register: %s\n",
					argv[i] + 17);
				return -1;
			}
		} else {
			fprintf(stderr, "qemu-etrace-plugin: invalid option: %s\n",
				argv[i]);
			return -1;
		}
	}
	if (hypervisor_filter && !tb_exec_output) {
		fprintf(stderr,
			"qemu-etrace-plugin: context filtering requires format v1\n");
		return -1;
	}
	if (hypervisor_filter && !nr_context_ranges) {
		fprintf(stderr,
			"qemu-etrace-plugin: context=hypervisor requires a context range\n");
		return -1;
	}
	if (nr_context_ranges && !hypervisor_filter) {
		fprintf(stderr,
			"qemu-etrace-plugin: context ranges require context=hypervisor\n");
		return -1;
	}
	if (exec_mapping && !tb_exec_output) {
		fprintf(stderr,
			"qemu-etrace-plugin: execution mappings require format v1\n");
		return -1;
	}
	if (context_register_basic
	    && !configure_basic_context(info->target_name)) {
		fprintf(stderr,
			"qemu-etrace-plugin: no basic context register set for %s\n",
			info->target_name);
		return -1;
	}
	context_enabled = hypervisor_filter || context_register_all
		|| context_register_names;
	if (context_enabled && !tb_exec_output) {
		fprintf(stderr,
			"qemu-etrace-plugin: context capture requires format v1\n");
		return -1;
	}
#if QEMU_PLUGIN_VERSION < 2
	if (context_register_all || context_register_names) {
		fprintf(stderr,
			"qemu-etrace-plugin: context registers require QEMU plugin "
			"API 2 or newer\n");
		return -1;
	}
#endif

	fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		fprintf(stderr, "qemu-etrace-plugin: %s: %s\n",
			output, strerror(errno));
		return -1;
	}
	if (gzip_output) {
		mode[2] = (char)('0' + gzip_level);
		trace_gz = gzdopen(fd, mode);
		if (!trace_gz) {
			fprintf(stderr, "qemu-etrace-plugin: %s: %s\n",
				output, strerror(errno));
			close(fd);
			return -1;
		}
		if (gzbuffer(trace_gz, 128 * 1024) != 0) {
			fprintf(stderr,
				"qemu-etrace-plugin: unable to allocate gzip buffer\n");
			gzclose(trace_gz);
			trace_gz = NULL;
			return -1;
		}
	} else {
		trace_fd = fd;
	}
	guest_address_bits = target_bits(info->target_name);
	if (!write_headers()) {
		fprintf(stderr, "qemu-etrace-plugin: %s: %s\n", output,
			output_error());
		if (trace_gz) {
			gzclose(trace_gz);
			trace_gz = NULL;
		} else {
			close(trace_fd);
			trace_fd = -1;
		}
		return -1;
	}

#if QEMU_PLUGIN_VERSION >= 2
	have_vcpu = false;
	max_vcpu_index = 0;
	exec_state = qemu_plugin_scoreboard_new(sizeof(struct vcpu_exec_state));
	if (!exec_state) {
		fprintf(stderr,
			"qemu-etrace-plugin: unable to allocate execution "
			"scoreboard\n");
		return -1;
	}
	exec_progress = qemu_plugin_scoreboard_u64_in_struct(
		exec_state, struct vcpu_exec_state, progress);
	if (context_register_all || context_register_names) {
#if QEMU_PLUGIN_VERSION >= 7
		qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
#else
		qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
#endif
	}
#if QEMU_PLUGIN_VERSION >= 7
	qemu_plugin_register_vcpu_exit_cb(id, vcpu_exit, NULL);
#else
	qemu_plugin_register_vcpu_exit_cb(id, vcpu_exit);
#endif
#endif

#if QEMU_PLUGIN_VERSION >= 7
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans, NULL);
#else
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
#endif
#ifdef HAVE_QEMU_PLUGIN_VCPU_DISCON_CB
#if QEMU_PLUGIN_VERSION >= 7
	qemu_plugin_register_vcpu_discon_cb(id, QEMU_PLUGIN_DISCON_ALL,
					   vcpu_discontinuity, NULL);
#else
	qemu_plugin_register_vcpu_discon_cb(id, QEMU_PLUGIN_DISCON_ALL,
					   vcpu_discontinuity);
#endif
#endif
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
	return 0;
}
