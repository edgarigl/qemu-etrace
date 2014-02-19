# QEMU etrace python class
# 
# Copyright (C) 2014 Edgar E. Iglesias
#
# This work is licensed under the terms of the GNU GPL, version 2.  See
# the COPYING file in the top-level directory.

import sys
from ctypes import *

class etrace_hdr(Structure):
	_pack_ = 1
	_fields_ = [
		("type", c_uint16),
		("unit_id", c_uint16),
		("len", c_uint32)
	]

class etrace_arch(Structure):
	_pack_ = 1
	_fields_ = [
		("arch_id", c_uint32),
		("arch_bits", c_uint8),
		("big_endian", c_uint8),
	]

class etrace_arch_gh(Structure):
	_pack_ = 1
	_fields_ = [
		("guest", etrace_arch),
		("host", etrace_arch)
	]

class etrace_exec_entry32(Structure):
	_pack_ = 1
	_fields_ = [
		("duration", c_uint32),
		("start", c_uint32),
		("end", c_uint32),
	]

class etrace_exec_p(Structure):
	_pack_ = 1
	_fields_ = [
		("nr", c_uint64),
		("ex32", POINTER(etrace_exec_entry32)),
	]

class etrace_exec(Structure):
	_pack_ = 1
	_fields_ = [
		("start_time", c_uint64),
	]

class etrace_mem(Structure):
	_pack_ = 1
	_fields_ = [
		("time", c_uint64),
		("vaddr", c_uint64),
		("paddr", c_uint64),
		("value", c_uint64),
		("attr", c_uint32),
		("size", c_uint8),
		("padd", c_uint8 * 3),
	]

class etrace_event_u64(Structure):
	_pack_ = 1
	_fields_ = [
		("flags", c_uint32),
		("unit_id", c_uint16),
		("reserved", c_uint16),
		("time", c_uint64),
		("val", c_uint64),
		("prev_val", c_uint64),
		("dev_name_len", c_uint16),
		("event_name_len", c_uint16),
	]

class etrace_all_subtypes(Union):
	_pack_ = 1
	_fields_ = [
		("p8", POINTER(c_uint8)),
		("dev_name", c_char_p),
		("event_name", c_char_p),
		("ex", etrace_exec_p),
		("arch", etrace_arch_gh),
		("mem", etrace_mem),
		("event_u64", etrace_event_u64),
		("texec", etrace_exec)
	]
class etrace_pkg(Structure):
	_pack_ = 1
	_fields_ = [
		("hdr", etrace_hdr),
		("all", etrace_all_subtypes)
	]

class etrace(object):
	TYPE_NONE = 0
	TYPE_EXEC = 1
	TYPE_TB = 2
	TYPE_NOTE = 3
	TYPE_MEM = 4
	TYPE_ARCH = 5
	TYPE_BARRIER = 6
	TYPE_EVENT_U64_OLD = 7
	TYPE_EVENT_U64 = 8
	TYPE_INFO = 0x4554

	MEM_READ  = (0 << 0)
	MEM_WRITE = (1 << 0)

	ETRACE_EVU64_F_PREV_VAL = (1 << 0)

	R_POS_CACHESIZE = 1024

	def __init__(self, f):
		self.debugf = None
		self.f = f

		self.reset()

	def debug(self, str):
		if self.debugf == None:
			self.debugf = open(".debug.etrace", 'w+')
		self.debugf.write(str)
		self.debugf.write("\n")

	def type_to_name(self, type):
		if type == self.TYPE_INFO:
			return "info"

		typenames = ["none", "exec", "tb", "note", "mem",
				"arch", "barrier", "event_u64"]
		return typenames[type]

	def push_pos(self):
		pos = self.f.tell()
		if len(self.r_pos_cache) == 0 or pos > self.r_pos_cache[0]:
			if self.r_idx > self.r_max_idx:
				self.r_max_idx = self.r_idx
			self.r_pos_cache.insert(0, pos)
			if len(self.r_pos_cache) > self.R_POS_CACHESIZE:
				self.r_pos_cache.pop()

	def reset(self):
		self.r_idx = 0
		self.r_max_idx = 0
		self.r_pos_cache = []
		self.f.seek(0, 0)

	def stepb(self):
		if self.r_idx <= 1:
			return None

		self.r_idx -= 1
		cache_idx = self.r_max_idx - self.r_idx + 1
		if cache_idx >= 0 and cache_idx < len(self.r_pos_cache):
			pos = self.r_pos_cache[cache_idx]
		else:
			self.r_max_idx = 0
			self.r_pos_cache = []
			self.f.seek(0, 0)
			i = 0
			while i < (self.r_idx - 2):
				self.push_pos()
				i += 1
				r = self.decode_record()
				if r == None:
					break
			self.r_idx = i
			return r
		self.f.seek(pos, 0)
		return self.decode_record()

	def stepf(self):
		self.push_pos()
		self.r_idx += 1
		return self.decode_record()

	def decode_record(self):
		pkg = etrace_pkg()
		self.f.readinto(pkg.hdr)
		pos = self.f.tell()

		if pkg.hdr.type == self.TYPE_NONE:
			return None

		end_pos = pos + pkg.hdr.len
		if pkg.hdr.type == self.TYPE_ARCH:
			self.f.readinto(pkg.all.arch)
			print sizeof(pkg.all.arch)
			self.arch = pkg.all.arch
			if self.arch.guest.arch_bits == 32:
				self.etype = etrace_exec_entry32
			else:
				assert False, "Unsupported arch bit %d" \
						% self.arch.arch_bits
			self.f.seek(end_pos, 0)

		elif pkg.hdr.type == self.TYPE_MEM:
			self.f.readinto(pkg.all.mem)
		elif pkg.hdr.type == self.TYPE_EVENT_U64:
			self.f.readinto(pkg.all.event_u64)
			dev_name = self.f.read(pkg.all.event_u64.dev_name_len - 1)
			dummy = self.f.read(1)
			ev_name = self.f.read(pkg.all.event_u64.event_name_len - 1)
			dummy = self.f.read(1)
			pkg.all.event_name = ev_name
			pkg.all.dev_name = dev_name
		elif pkg.hdr.type == self.TYPE_EXEC:
			len = (pkg.hdr.len - sizeof(pkg.all.texec))
			len /= sizeof(self.etype)
			a = (self.etype * len)()
			self.f.readinto(pkg.all.texec)
			self.f.readinto(a)
			pkg.all.ex.nr = len
			if self.arch.guest.arch_bits == 32:
				pkg.all.ex.ex32 = cast(a, POINTER(self.etype))
		else:
			self.f.seek(end_pos, 0)

		return pkg
