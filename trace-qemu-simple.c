/*
 * This file is part of qemu-etrace.
 *
 * Copyright (c) 2019 Luc Michel <luc.michel@greensocs.com>
 *
 * qemu-etrace is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * qemu-etrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with qemu-etrace.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <gmodule.h>
#include <sys/ioctl.h>

#include "util.h"
#include "trace-qemu-simple.h"
#include "syms.h"
#include "safeio.h"

#define PRINT_ERR(fmt, ...) \
	fprintf(stderr, "trace-qemu-simple: " fmt, ## __VA_ARGS__)

#if 0
#define QEMU_SIMPLE_DEBUG
#endif

#ifdef QEMU_SIMPLE_DEBUG
#define PRINT_DBG(fmt, ...) \
	fprintf(stderr, "[dbg] trace-qemu-simple: " fmt, ## __VA_ARGS__)
#else
#define PRINT_DBG(fmt, ...) do {} while(0)
#endif

/** Trace file header event ID, picked to avoid conflict with real event IDs */
#define HEADER_EVENT_ID (~(uint64_t)0)

/** Trace file magic number */
#define HEADER_MAGIC 0xf2b177cb0aa429b4ULL

/** Trace file version number, bump if format changes */
#define HEADER_VERSION 4

/** Records were dropped event ID */
#define DROPPED_EVENT_ID (~(uint64_t)0 - 1)

#define TRACE_RECORD_TYPE_MAPPING 0
#define TRACE_RECORD_TYPE_EVENT   1

/** Trace buffer entry */
typedef struct {
	uint64_t event; /* event ID value */
	uint64_t timestamp_ns;
	uint32_t length;   /*    in bytes */
	uint32_t pid;
	uint64_t arguments[];
} TraceRecord;

typedef struct {
	uint64_t header_event_id; /* HEADER_EVENT_ID */
	uint64_t header_magic;    /* HEADER_MAGIC    */
	uint64_t header_version;  /* HEADER_VERSION  */
} TraceLogHeader;

static const size_t READ_BUF_SZ = 256 * 1024 * 1024;

typedef struct qemu_simple_tracer {
	struct tracer tr;
	GHashTable *trace_events;
	unsigned int dropped_ev;

	uint64_t *args_buf;
	size_t args_buf_len;

	enum cov_format cov_fmt;

	uint8_t *trace_buf;
	size_t read_cur, write_cur;
} qemu_simple_tracer;

static inline size_t trace_buf_data_available(qemu_simple_tracer *t)
{
	return t->write_cur - t->read_cur;
}

static ssize_t fill_trace_buf(qemu_simple_tracer *t, size_t min_read)
{
	int count, rel_write_cur;
	ssize_t ret;

	ret = ioctl(t->tr.fd, FIONREAD, &count);

	if (ret) {
		return -1;
	}

	/* Even if count is 0, try to read so we can wait for data and detect EOF */
	if (count == 0) {
		count = min_read;
	}

	rel_write_cur = t->write_cur % READ_BUF_SZ;

	count = MIN(count, READ_BUF_SZ - trace_buf_data_available(t));
	count = MIN(count, READ_BUF_SZ - rel_write_cur);

	ret = safe_read(t->tr.fd, t->trace_buf + rel_write_cur, count);

	if (ret > 0) {
		t->write_cur += ret;
	}

	return ret;
}

static ssize_t read_trace_buf(qemu_simple_tracer *t, void *data, size_t len)
{
	int rel_read_cur;
	ssize_t ret;
	uint8_t *pdata = (uint8_t *) data;

	while (trace_buf_data_available(t) < len) {
		ssize_t fill_ret = fill_trace_buf(t, len);
		if (fill_ret < 0) {
			return -1;
		}
		if (fill_ret == 0) {
			/* EOF. Keep going to empty the buffer out. */
			break;
		}
	}

	len = MIN(len, trace_buf_data_available(t));
	ret = len;

	rel_read_cur = t->read_cur % READ_BUF_SZ;

	if (READ_BUF_SZ - rel_read_cur < len) {
		size_t first_part = READ_BUF_SZ - rel_read_cur;
		memcpy(pdata, t->trace_buf + rel_read_cur, first_part);
		pdata += first_part;
		len -= first_part;
		t->read_cur += first_part;
		rel_read_cur = 0;
	}

	memcpy(pdata, t->trace_buf + rel_read_cur, len);
	t->read_cur += len;

	return ret;
}

static void handle_tb_enter_exec(qemu_simple_tracer *t, const TraceRecord *r)
{
	uint64_t pc_start, pc_end, duration;
	struct sym *sym = NULL;

	duration = 0;
	pc_start = t->args_buf[1];
	pc_end = t->args_buf[2];

	PRINT_DBG("trace tb_enter_exec: timestamp: %"PRIu64
			" pc_start: %08"PRIx64", pc_end: %08"PRIx64"\n",
			r->timestamp_ns, pc_start, pc_end);

	if (t && t->tr.sym_tree && *t->tr.sym_tree) {
		sym = sym_lookup_by_addr(t->tr.sym_tree, pc_start);
	} else {
		sym = sym_get_unknown(t->tr.sym_tree);
	}

	if (t->cov_fmt != NONE) {
		if (sym) {
			uint64_t addr = pc_start;
			while (sym && addr < pc_end) {
				uint64_t tend = pc_end;

				if (tend > (sym->addr + sym->size)) {
					tend = sym->addr + sym->size;
					PRINT_ERR("WARNING: fixup sym %s has spans "
					"over to another symbol\n", sym->name);
				}

				sym_update_cov(sym, addr, tend, duration);
				addr = tend;
				sym = sym_lookup_by_addr(t->tr.sym_tree, addr);
			}
		}
	}
}

static void handle_trace(qemu_simple_tracer *t, const char *name,
						 const TraceRecord *r)
{
	if (!strcmp(name, "tb_enter_exec")) {
		handle_tb_enter_exec(t, r);
	} else {
		PRINT_DBG("Ignoring trace %s\n", name);
	}
}

static void resize_args_buf(qemu_simple_tracer *t, size_t new_len)
{
	size_t args_len = new_len - sizeof(TraceRecord);

	if (args_len > t->args_buf_len) {
		t->args_buf = safe_realloc(t->args_buf, args_len);
		t->args_buf_len = args_len;
	}
}

static bool read_header(qemu_simple_tracer *t)
{
	TraceLogHeader hdr;

	ssize_t ret = read_trace_buf(t, &hdr, sizeof(hdr));

	if (ret < sizeof(hdr)) {
		PRINT_ERR("cannot read header\n");
		return false;
	}

	if (hdr.header_event_id != HEADER_EVENT_ID) {
		PRINT_ERR("invalid QEMU simple trace file\n");
		return false;
	}

	if (hdr.header_magic != HEADER_MAGIC) {
		PRINT_ERR("invalid QEMU simple trace file\n");
		return false;
	}

	if (hdr.header_version != HEADER_VERSION) {
		PRINT_ERR("Unsupported simple trace file version %" PRIu64 "\n", hdr.header_version);
		return false;
	}

	PRINT_DBG("header: version: %"PRIu64"\n", hdr.header_version);
	return true;
}

enum read_record_sta {
	REC_OK = 0,
	REC_EOF,
	REC_ERR,
};

static enum read_record_sta read_record_mapping(qemu_simple_tracer *t)
{
	uint64_t id;
	uint32_t len;
	char *name = NULL;
	ssize_t ret = read_trace_buf(t, &id, sizeof(id));

	if (ret < sizeof(id)) {
		PRINT_ERR("Unexpected end of file while reading trace\n");
		return REC_EOF;
	}

	ret = read_trace_buf(t, &len, sizeof(len));

	if (ret < sizeof(len)) {
		PRINT_ERR("Unexpected end of file while reading trace\n");
		return REC_EOF;
	}

	if (len > 4096) {
		PRINT_ERR("Error while reading trace file: trace name lenght too large in mapping\n");
		return REC_ERR;
	}

	name = safe_malloc(len + 1);
	ret = read_trace_buf(t, name, len);
	name[len] = '\0';

	if (ret < len) {
		PRINT_ERR("Unexpected end of file while reading trace\n");
		free(name);
		return REC_EOF;
	}

	PRINT_DBG("mapping: %"PRIu64" -> %s\n", id, name);

	gboolean r = g_hash_table_insert(t->trace_events, GINT_TO_POINTER(id), name);

	g_assert(r == TRUE);

	return REC_OK;
}

static enum read_record_sta read_record_event(qemu_simple_tracer *t)
{
	TraceRecord rec;
	const char *trace_name;

	ssize_t ret = read_trace_buf(t, &rec, sizeof(rec));

	if (ret < sizeof(rec)) {
		PRINT_ERR("Unexpected end of file while reading trace\n");
		return REC_EOF;
	}

	if (rec.length < sizeof(rec) || rec.length > 4096) {
		PRINT_ERR("Bad record size: %"PRIu32"\n", rec.length);
		return REC_ERR;
	}

	resize_args_buf(t, rec.length);

	PRINT_DBG("Reading args: %lu\n", rec.length - sizeof(TraceRecord));

	ret = read_trace_buf(t, t->args_buf, rec.length - sizeof(TraceRecord));

	if (ret < rec.length - sizeof(TraceRecord)) {
		PRINT_ERR("Unexpected end of file while reading trace\n");
		return REC_EOF;
	}

	PRINT_DBG("record: event:%"PRIu64"\n", rec.event);

	if (rec.event == DROPPED_EVENT_ID) {
		PRINT_ERR("Warning: %"PRIu64" event dropped by QEMU\n",
			  t->args_buf[0]);
		t->dropped_ev += t->args_buf[0];
		return REC_OK;
	} else if (!g_hash_table_contains(t->trace_events, GINT_TO_POINTER(rec.event))) {
		PRINT_ERR("Encountered unknown event id %"PRIu64". Ignoring\n",
			  rec.event);
		return REC_OK;
	}

	trace_name = g_hash_table_lookup(t->trace_events, GINT_TO_POINTER(rec.event));

	handle_trace(t, trace_name, &rec);

	return REC_OK;
}


static enum read_record_sta read_record(qemu_simple_tracer *t)
{
	uint64_t type;

	ssize_t ret = read_trace_buf(t, &type, sizeof(type));

	if (ret < sizeof(type)) {
		return REC_EOF;
	}

	PRINT_DBG("record type: %"PRIu64"\n", type);

	switch (type) {
	case TRACE_RECORD_TYPE_EVENT:
		return read_record_event(t);
	case TRACE_RECORD_TYPE_MAPPING:
		return read_record_mapping(t);
	default:
		PRINT_ERR("Error while reading trace file: unknown record type\n");
		return REC_ERR;
	}
}

void qemu_simple_trace_show(int fd, FILE *fp_out,
							const char *objdump, const char *machine,
							const char *guest_objdump, const char *guest_machine,
							void **sym_tree, enum cov_format cov_fmt,
							enum trace_format trace_in_fmt,
							enum trace_format trace_out_fmt)
{
	qemu_simple_tracer t;
	enum read_record_sta sta;

	t.tr.fd = fd;
	t.tr.fp_out = fp_out;
	t.tr.sym_tree = sym_tree;
	t.tr.host.objdump = objdump;
	t.tr.host.machine = machine;
	t.tr.guest.objdump = guest_objdump;
	t.tr.guest.machine = guest_machine;
	t.dropped_ev = 0;
	t.args_buf = NULL;
	t.args_buf_len = 0;
	t.trace_events = g_hash_table_new_full(NULL, NULL, NULL, free);
	t.cov_fmt = cov_fmt;
	t.read_cur = 0;
	t.write_cur = 0;
	t.trace_buf = safe_malloc(READ_BUF_SZ);

	if (!read_header(&t)) {
		exit(1);
	}

	do {
		sta = read_record(&t);
	} while (sta == REC_OK);

	if (sta == REC_ERR) {
		exit(1);
	}

	free(t.args_buf);
	free(t.trace_buf);
	g_hash_table_destroy(t.trace_events);
}
