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
	uint64_t start;
	uint64_t end;
};

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

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct tb_data *translated_blocks;
static int trace_fd = -1;
static gzFile trace_gz;
static bool trace_failed;
static uint8_t guest_address_bits;
static int gzip_level = Z_BEST_SPEED;
static bool gzip_output;

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
			.attr = 0,
			.version = { .major = 0, .minor = 0 },
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

static void vcpu_tb_exec(unsigned int cpu_index, void *userdata)
{
	const struct tb_data *tb = userdata;
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
			.start = (uint32_t)tb->start,
			.end = (uint32_t)tb->end,
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
			.start = tb->start,
			.end = tb->end,
		},
	};

	if (guest_address_bits == 32)
		write_packet(&packet32, sizeof(packet32));
	else
		write_packet(&packet, sizeof(packet));
}

#if QEMU_PLUGIN_VERSION >= 7
static void vcpu_tb_trans(struct qemu_plugin_tb *tb, void *userdata)
#else
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
#endif
{
	struct qemu_plugin_insn *last_insn;
	struct tb_data *data;
	uint64_t last_addr;
	size_t n_insns;
	size_t last_size;

#if QEMU_PLUGIN_VERSION >= 7
	(void) userdata;
#else
	(void) id;
#endif

	n_insns = qemu_plugin_tb_n_insns(tb);
	if (n_insns == 0)
		return;

	last_insn = qemu_plugin_tb_get_insn(tb, n_insns - 1);
	last_addr = qemu_plugin_insn_vaddr(last_insn);
	last_size = qemu_plugin_insn_size(last_insn);

	data = calloc(1, sizeof(*data));
	if (!data) {
		fprintf(stderr, "qemu-etrace-plugin: unable to allocate TB data\n");
		return;
	}
	data->start = qemu_plugin_tb_vaddr(tb);
	if (last_size > UINT64_MAX - last_addr)
		data->end = UINT64_MAX;
	else
		data->end = last_addr + last_size;

	pthread_mutex_lock(&lock);
	data->next = translated_blocks;
	translated_blocks = data;
	pthread_mutex_unlock(&lock);

	qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
					     QEMU_PLUGIN_CB_NO_REGS, data);
}

#if QEMU_PLUGIN_VERSION >= 7
static void plugin_exit(void *userdata)
#else
static void plugin_exit(qemu_plugin_id_t id, void *userdata)
#endif
{
	struct tb_data *tb;

#if QEMU_PLUGIN_VERSION < 7
	(void) id;
#endif
	(void) userdata;

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
	gzip_level = Z_BEST_SPEED;
	trace_failed = false;
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

#if QEMU_PLUGIN_VERSION >= 7
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans, NULL);
#else
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
#endif
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
	return 0;
}
