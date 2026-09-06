/*
 * QEMU TCG plugin for ETrace execution records.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
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
	struct {
		uint64_t start;
		uint64_t end;
	} insns[];
};

#if QEMU_PLUGIN_VERSION >= 2
struct vcpu_exec_state {
	struct tb_data *pending;
	uint64_t progress;
	uint64_t sequence;
	bool seen;
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
static uint64_t next_tb_id;
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
				| (tb_exec_output ? ETRACE_INFO_F_TB_EXEC : 0),
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

	return write_output(&info_packet, sizeof(info_packet))
		&& write_output(&arch_packet, sizeof(arch_packet));
}

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
		+ tb->n_insns * sizeof(*insns);
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
	definition->size = tb->end - tb->start;
	definition->insn_count = tb->n_insns;
	for (i = 0; i < tb->n_insns; i++) {
		insns[i].offset = tb->insns[i].start - tb->start;
		insns[i].size = tb->insns[i].end - tb->insns[i].start;
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
			       uint64_t sequence, uint64_t progress)
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
			.insn_count = (uint16_t)progress,
		},
	};

	write_packet(&packet, sizeof(packet));
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

static bool write_exec_prefix(unsigned int cpu_index,
			      const struct tb_data *tb, uint64_t end)
{
	if (tb_exec_output) {
		struct vcpu_exec_state *state;

		if (!end)
			return true;
		if (end > tb->n_insns)
			return false;
		state = qemu_plugin_scoreboard_find(exec_state, cpu_index);
		write_tb_execution(cpu_index, tb, ++state->sequence, end);
		return true;
	}
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
	uint64_t progress;

	state = qemu_plugin_scoreboard_find(exec_state, cpu_index);
	record_vcpu(state, cpu_index);
	progress = qemu_plugin_u64_get(exec_progress, cpu_index);
	if (state->pending
	    && !write_exec_prefix(cpu_index, state->pending, progress))
		increment_status_counter(&producer_status.unresolved_tb_exits);
	state->pending = current;
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
		qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
			insn, QEMU_PLUGIN_INLINE_STORE_U64,
			exec_progress,
			tb_exec_output ? i + 1 : data->insns[i].end);
	}
	if (tb_exec_output)
		write_tb_definition(data);
	qemu_plugin_register_vcpu_tb_exec_cb(
		tb, vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, data);
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

	write_packet(&status_packet, sizeof(status_packet));

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

		free(tb);
		tb = next;
	}

#if QEMU_PLUGIN_VERSION >= 2
	if (exec_state) {
		qemu_plugin_scoreboard_free(exec_state);
		exec_state = NULL;
	}
#endif
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
	gzip_level = Z_BEST_SPEED;
	trace_failed = false;
	next_tb_id = 0;
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
		} else {
			fprintf(stderr, "qemu-etrace-plugin: invalid option: %s\n",
				argv[i]);
			return -1;
		}
	}

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
